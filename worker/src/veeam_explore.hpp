#pragma once

// What VeeamM365Connector's restore_sample (W2.5) and list_candidates (W2.6)
// share: finding the client's organisation, checking the restore point, the
// preflight, and the explore sessions a call opens and must stop again
// (docs/api/veeam-restore-flow.md §2-§3, §13; docs/decisions.md 2026-09-30,
// W2.6 point 11). Moved out of veeam_m365_connector.cpp without a change in
// behaviour.

#include <rp/connector.hpp>
#include <rp/veeam_client.hpp>

#include <spdlog/logger.h>

#include <chrono>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace rp::veeam_explore {

// A client reference as error messages show it: each control character
// (control_chars.hpp), which could forge, hide or reorder a log or stderr
// line, becomes a space. client_ref will come from a Cloud job (C5.6).
std::string shown(std::string_view client_ref);

// Logs `line` as a warning, redacted and on one line; never throws. A null
// logger is spdlog's default one.
void warn(const std::shared_ptr<spdlog::logger>& logger, const std::string& line) noexcept;

// The organisation named `client_ref` (ASCII case-insensitive), exactly one,
// with a UUID. None is connector::NotFoundError, several or an ID that isn't
// a UUID connector::Error; Veeam's errors pass through.
Organization find_organization(VeeamClient& client, const std::string& client_ref);

// Veeam explores the newest data at or before an explore POST's dateTime
// (veeam-notes §4.2), whatever point that is: `wanted` must be one of the
// organisation's points (by ID), its time byte for byte, or the result would
// name a point it didn't browse. connector::Error otherwise, its message
// ending "; " + `outcome` (e.g. "nothing was restored").
void check_restore_point(VeeamClient& client, const std::string& organization_id,
                         const std::string& client_ref, const connector::RestorePoint& wanted,
                         std::string_view outcome);

// No restore session of `account` Working in Veeam (GET
// /v8/RestoreSessions?limit=200), else connector::Error naming them, ending
// "; " + `outcome`.
void preflight(VeeamClient& client, const std::string& account, std::string_view outcome);

// The explore sessions one call opens, and their closing. The destructor
// stops each one still Working (best effort, never throws) unless
// keep_open(true) says a restore may still run under them.
class ExploreSessions {
public:
    struct Context {
        VeeamClient& client;
        const std::function<std::chrono::system_clock::time_point()>& wall_now;
        const std::shared_ptr<spdlog::logger>& logger;
        const std::string& account; // as Veeam lists it in initiatedBy
        const std::string& backup_time;
    };

    explicit ExploreSessions(Context context) : c_(context) {}
    ExploreSessions(const ExploreSessions&) = delete;
    ExploreSessions& operator=(const ExploreSessions&) = delete;
    ~ExploreSessions() { close(); }

    // The organisation the sessions are opened on; `name` as Veeam names it
    // in a session's "organization".
    void set_organization(std::string id, std::string name);

    // Opens an explore session of `kind` on the restore point and records
    // its ID at once. A failed POST (not a refused sign-in) first adopts the
    // one session of ours it may have opened anyway, then rethrows.
    std::string open(connector::ItemKind kind);

    // Records a session ID the duplicate check must not take for a new one.
    void know(const std::string& id) { known_.insert(id); }

    // The duplicate check (restore-flow §8): our account's sessions of this
    // type and organisation, new since `posted`, not already known; with
    // `working_only`, only the Working ones.
    std::vector<std::string> duplicates(connector::ItemKind kind,
                                        std::chrono::system_clock::time_point posted,
                                        bool working_only = false);

    // Whether a restore may still be running under the sessions: then they
    // are left open. `running` names the restore session, if one is known.
    void keep_open(bool keep, std::string running = {});
    bool kept_open() const noexcept { return keep_open_; }

    // When kept open: the sessions left open, for the message of whatever
    // ends the call; empty otherwise.
    std::string left_open() const;

    // Every explore session opened, in order.
    const std::vector<std::string>& opened() const noexcept { return opened_; }

    // Stops each session still Working, unless kept open; never throws.
    void close() noexcept;

    // Stops each session still Working and forgets them all; returns those
    // it couldn't read or stop (each also logged).
    std::vector<std::string> close_checked();

private:
    void adopt_orphans(connector::ItemKind kind, std::chrono::system_clock::time_point sent) noexcept;
    // Stops `id` if it is Working; an error is logged and returns false.
    bool stop_if_working(const std::string& id) noexcept;

    Context c_;
    std::string organization_id_;
    std::string organization_name_;
    std::vector<std::string> opened_; // explore sessions, in order
    std::set<std::string> known_;     // every session ID the call knows
    bool keep_open_ = false;
    std::string running_session_;
};

} // namespace rp::veeam_explore
