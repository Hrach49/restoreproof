#pragma once

// The Veeam Backup for Microsoft 365 connector (W1.7), registered as
// "veeam_m365" (rp/connector_registry.hpp). It speaks Veeam's REST API v8
// through rp::VeeamClient (W1.5) and turns Veeam's types and errors into the
// connector ones, so nothing past IConnector sees Veeam. The choices are the
// 2026-09-27 W1.7 entry in docs/decisions.md.

#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>
#include <rp/veeam_client.hpp>

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

class VeeamM365Connector final : public connector::IConnector {
public:
    // The REST API version the connector speaks: describe()'s version.
    static constexpr std::string_view kApiVersion = "v8";

    // Owns `http` and the VeeamClient on it. The other arguments are
    // VeeamClient's, and so are the std::invalid_argument it throws (a URL
    // that isn't https://, an empty username or password, ...). A null `http`
    // is std::invalid_argument too. Makes no request.
    VeeamM365Connector(std::unique_ptr<IHttpClient> http, std::string base_url,
                       std::string username, std::string password,
                       VeeamClientOptions options = {});

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

    // Throws connector::NotImplementedError, before any request: the restore
    // comes with W2.5, which calls TargetGuard (W2.7, rp/target_guard.hpp and
    // rp/target_guard_veeam.hpp) first.
    connector::RestoreResult restore_sample(const connector::RestoreSpec& spec) override;

private:
    std::unique_ptr<IHttpClient> http_;
    std::unique_ptr<VeeamClient> client_;
};

// The registry's factory for "veeam_m365": a VeeamM365Connector on
// Config::veeam_url with the Veeam secrets, through an HTTP client from
// `options.make_http` (rp::HttpClient when null) whose CA file and pin are
// Config::veeam_ca_file and veeam_cert_sha256 (TLS is never off). Throws
// ConfigError "RP_VEEAM_USERNAME is not set" (then RP_VEEAM_PASSWORD), keyed
// by the variable, for a missing or empty secret, before making anything.
std::unique_ptr<connector::IConnector> make_veeam_m365_connector(
    const Config& config, const Secrets& secrets, const connector::ConnectorOptions& options);

} // namespace rp
