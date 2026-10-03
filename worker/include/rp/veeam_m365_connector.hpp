#pragma once

// The Veeam Backup for Microsoft 365 connector (W1.7), registered as
// "veeam_m365" (rp/connector_registry.hpp). It speaks Veeam's REST API v8
// through rp::VeeamClient (W1.5) and turns Veeam's types and errors into the
// connector ones, so nothing past IConnector sees Veeam. The choices are the
// 2026-09-27 W1.7 entry in docs/decisions.md.

#include <rp/cert_export.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/graph_client.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>
#include <rp/target_guard.hpp>
#include <rp/veeam_client.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

// The Graph client the target guard reads through, and the HTTP client it
// sends on when the connector is to own that.
struct VeeamM365GraphParts {
    std::unique_ptr<IHttpClient> http;
    std::shared_ptr<graph::GraphClient> client;
};

// What a VeeamM365Connector takes besides Veeam's address and account.
// Every field may be left empty; restore_sample needs `graph` (or
// `make_graph`) and `cert_exporter`.
struct VeeamM365ConnectorOptions {
    // VeeamClient's: logger, the steady clock (tokens, and restore_sample's
    // 20-minute deadline), the wait (retries, and restore_sample's polls),
    // jitter, page size, timeout.
    VeeamClientOptions client;
    // The Worker app's Graph client the target guard reads through; null:
    // restore_sample refuses to run.
    std::shared_ptr<graph::GraphClient> graph;
    // The HTTP client `graph` sends through, when the connector is to own it;
    // kept alive as long as `graph`.
    std::unique_ptr<IHttpClient> graph_http;
    // With `graph` null: makes both on the first restore_sample (the
    // registry's factory), so listing restore points needs nothing of Graph.
    // What it throws (a CertificateError, a ConfigError) passes out of
    // restore_sample as it is, before any request; it is tried again next
    // time.
    std::function<VeeamM365GraphParts()> make_graph;
    // Where the guard logs a refusal.
    TargetGuardOptions guard;
    // Exports Veeam's organisation app certificate for each restore POST;
    // null: restore_sample refuses before any explore session.
    std::shared_ptr<CertificateExporter> cert_exporter;
    // The wall clock of the duplicate check (restore-flow §8); null =
    // system_clock::now.
    std::function<std::chrono::system_clock::time_point()> wall_now;
};

class VeeamM365Connector final : public connector::IConnector {
public:
    // The REST API version the connector speaks: describe()'s version.
    static constexpr std::string_view kApiVersion = "v8";

    // Owns `http` and the VeeamClient on it. The other arguments are
    // VeeamClient's (options.client too), and so are the
    // std::invalid_argument it throws (a URL that isn't https://, an empty
    // username or password, ...). A null `http` is std::invalid_argument too.
    // Makes no request.
    VeeamM365Connector(std::unique_ptr<IHttpClient> http, std::string base_url,
                       std::string username, std::string password,
                       VeeamM365ConnectorOptions options = {});

    // Logs out of Veeam if a call signed in (best effort, never throws).
    ~VeeamM365Connector() override;

    VeeamM365Connector(const VeeamM365Connector&) = delete;
    VeeamM365Connector& operator=(const VeeamM365Connector&) = delete;

    // {"veeam_m365", "v8"}.
    connector::ConnectorInfo describe() const override;

    // `client_ref` is the organisation's name, as Config::veeam_org_name,
    // matched ASCII case-insensitively against GET /v8/Organizations (as
    // `rpworker veeam list` marks it); then that organisation's restore
    // points, newest first. Veeam's errors become connector errors with the
    // same (redacted) message: AuthError -> connector::AuthError,
    // TransientError -> connector::TransientError, NotFoundError (the
    // organisation vanished between the two calls) -> connector::NotFoundError,
    // any other VeeamError -> connector::Error. No organisation of that name
    // -> connector::NotFoundError; more than one -> connector::Error; an
    // organisation ID that isn't a UUID -> connector::Error. An empty
    // `client_ref` is std::invalid_argument, before any request.
    std::vector<connector::RestorePoint> list_restore_points(const std::string& client_ref) override;

    // Restores `spec` (W2.5; docs/api/veeam-restore-flow.md, the 2026-09-30
    // W2.5 entry in docs/decisions.md). In order:
    //  1. the target guard's layer 1 (W2.7, rp/target_guard.hpp), before any
    //     Veeam request: every item checked, each target the spec uses
    //     resolved through Graph (made by options.make_graph if need be); a
    //     refusal is its connector::SafetyViolation; Graph's errors pass out
    //     as Graph's (rp/graph_errors.hpp), of their own type, their message
    //     ending with connector::kNothingRestored, so the run blames Graph and
    //     not the backup product (a target Graph can't find is a
    //     graph::NotFoundError, never connector::NotFoundError); without a
    //     Graph client connector::Error, no request. An empty spec
    //     then returns not_run, still without one;
    //  2. the organisation, as list_restore_points finds it (none is
    //     connector::Error here), whose settings must be of the expected
    //     shape and whose Exchange and SharePoint apps must be set and the
    //     same (connector::Error); without a certificate exporter
    //     connector::Error. The spec's restore point must be one of the
    //     organisation's (by ID), with its backup_time byte for byte
    //     (connector::Error): Veeam would otherwise explore whatever point is
    //     at or before that time;
    //  3. a preflight: no restore session of this account Working in Veeam
    //     (connector::Error, stop them with 08-sweep-sessions.ps1);
    //  4. for each type with items (mail, SharePoint, OneDrive) an explore
    //     session on the restore point, every item found in it by listing
    //     (exactly one match each; several connector::Error; a mailbox is a
    //     primary one, never an archive) and re-read. An item with no match
    //     (it, or its mailbox, folder, site, library or OneDrive, isn't in the
    //     restore point) is never sent: its result is
    //     ItemOutcome::not_in_backup with browsing's message, and the other
    //     items go ahead (Q3.1). The test OneDrive missing from the point is
    //     connector::Error;
    //  5. one restore call per source container, same-named items in separate
    //     calls: the body built, the certificate exported, layer 2
    //     (rp/target_guard_veeam.hpp) on the exact path and text, then one
    //     POST, never resent. A 4xx: connector::AuthError (401, 403) or
    //     connector::Error. No session ID: the duplicate check, up to three
    //     more looks 10 s apart; exactly one candidate is polled, else (or if
    //     the check fails) connector::Error. A session ID the check doesn't
    //     list alone (or a check that failed) is polled, then connector::Error
    //     (no verdict), with the explore sessions left open, as another
    //     candidate may still run;
    //  6. each restore session polled every 5 s until Stopped; a 404 or six
    //     failed polls in a row connector::Error, still Working after 20
    //     minutes connector::TransientError; then its statistics and events
    //     (connector::Error if unreadable), and its verdict. A session that
    //     restored nothing for an infrastructure reason, or without a word
    //     about any item, is connector::Error.
    // Every explore session opened is stopped at the end if still Working,
    // unless a restore may still be running (no verdict on the POST, a
    // timeout, a 404, failing polls): then they are left open and named in the
    // error. Veeam's errors map as list_restore_points maps them, but for
    // NotFoundError, which is connector::Error; restore_sample never throws
    // connector::NotFoundError (step 4 reports such an item instead). With
    // every item missing from the point, nothing is sent and the status is
    // `failed`; with some, `partial` at best. The spec's client_ref
    // must be set and its backup_time Veeam's UTC form (std::invalid_argument,
    // before any Veeam request).
    connector::RestoreResult restore_sample(const connector::RestoreSpec& spec) override;

    // Lists the random half's candidates in `query`'s restore point (W2.6;
    // docs/decisions.md 2026-09-30, W2.6 point 6). With no type asked for it
    // returns an empty pool without a request; an empty client_ref or a
    // backup_time that isn't Veeam's UTC form (or a negative limit) is
    // std::invalid_argument, before any request. Then, in order:
    //  1. the organisation, as list_restore_points finds it (none is
    //     connector::Error here), the restore point (one of its points, the
    //     backup_time byte for byte) and the preflight (no session of this
    //     account Working), each connector::Error, before any explore session;
    //  2. for each type asked for (mail, SharePoint, OneDrive) one explore
    //     session, and a two-level draw from sampling::stream_seed(query.seed,
    //     type, Stream::browse): the eligible containers (mailboxes, sites,
    //     OneDrives) sorted and drawn one at a time, in each the eligible
    //     folders sorted and up to limits.folders_per_container drawn and
    //     listed, until limits.containers_wanted containers gave a candidate or
    //     limits.containers_tried were looked into. The eligible OneDrives come
    //     from the explore session alone; a drawn one that no single user of
    //     GET /v8/Organizations/{id}/Users (today's users) owns is walked and
    //     drawn as the others, so the draw doesn't change, but nothing in it
    //     is listed (BrowseRecord::containers_unresolved). An item is a candidate only
    //     if restore_sample's own listing will find it exactly once, and never
    //     from a restore target or a canary location;
    //  3. every explore session stopped; one that couldn't be is
    //     connector::Error, as restore_sample's preflight would then refuse.
    // Each explore session opened is remembered, even when the call throws,
    // and restore_sample's duplicate check never counts one of them. Each
    // call first forgets those remembered more than 60 s before
    // (veeam_restore::kDuplicateWindow): the check only counts sessions made
    // 5 s before its POST or later, so the service's memory doesn't grow.
    // A random SharePoint item's drive_id is derived from Veeam's GUIDs
    // (src/graph_ids.hpp), so no Graph read is made. Veeam's errors map as
    // restore_sample maps them (a 404 is connector::Error); never
    // connector::NotFoundError. Sends no POST but the sign-in's, the explore
    // sessions' and their Stop.
    connector::CandidatePool list_candidates(const connector::CandidateQuery& query) override;

    // How many explore sessions list_candidates remembers (for tests).
    std::size_t candidate_sessions_remembered() const noexcept { return candidate_sessions_.size(); }

private:
    // Destroyed in reverse: the Graph client before its HTTP client, and the
    // VeeamClient before its.
    std::unique_ptr<IHttpClient> http_;
    std::unique_ptr<IHttpClient> graph_http_;
    std::unique_ptr<VeeamClient> client_;
    std::shared_ptr<graph::GraphClient> graph_;
    std::function<VeeamM365GraphParts()> make_graph_;
    TargetGuardOptions guard_options_;
    std::shared_ptr<CertificateExporter> cert_exporter_;
    std::function<std::chrono::system_clock::time_point()> wall_now_;
    std::function<std::chrono::steady_clock::time_point()> now_;
    std::function<void(std::chrono::milliseconds)> sleep_;
    std::shared_ptr<spdlog::logger> logger_;
    std::string account_; // the username as Veeam lists it in initiatedBy
    // Every explore session list_candidates opened (or adopted), stopped or
    // not, with when it was remembered (wall clock): Veeam lists them in
    // /v8/RestoreSessions with a restore's type, so restore_sample's
    // duplicate check knows them and never takes one for a second restore
    // (docs/decisions.md 2026-09-30, W2.6 point 11).
    std::map<std::string, std::chrono::system_clock::time_point> candidate_sessions_;
};

// The registry's factory for "veeam_m365": a VeeamM365Connector on
// Config::veeam_url with the Veeam secrets, through an HTTP client from
// `options.make_http` (rp::HttpClient when null) whose CA file and pin are
// Config::veeam_ca_file and veeam_cert_sha256 (TLS is never off); and
// `options.cert_exporter` (make_local_machine_cert_exporter when null).
// Checks first, before making any HTTP client: ConfigError "RP_VEEAM_USERNAME
// is not set" (then RP_VEEAM_PASSWORD), keyed by the variable, for a missing
// or empty secret. The Graph client for the target guard is made on the first
// restore_sample (make_graph), so listing restore points needs nothing of
// Graph: on the Worker app's certificate (graph::certificate_from_secrets at
// options.wall_now) and Config::graph_tenant_id and graph_client_id, through
// an HTTP client from `options.make_graph_http` (graph::make_graph_http_client
// when null). There, before any HTTP client and any request, the
// certificate's CertificateError (keyed by the variable when one is unset)
// and a ConfigError for a Graph ID that isn't a GUID pass out of
// restore_sample. Every part logs to options.logger (make_command_logger()'s
// when null). Sends nothing.
std::unique_ptr<connector::IConnector> make_veeam_m365_connector(
    const Config& config, const Secrets& secrets, const connector::ConnectorOptions& options);

} // namespace rp
