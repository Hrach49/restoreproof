#include <rp/veeam_m365_connector.hpp>

#include <rp/graph_errors.hpp>

#include "control_chars.hpp"
#include "uuid.hpp"

#include <algorithm>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp {

namespace {

bool ascii_iequals(std::string_view a, std::string_view b) noexcept
{
    const auto lower = [](char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    };
    return std::ranges::equal(a, b, [&](char x, char y) { return lower(x) == lower(y); });
}

// A client reference as error messages show it: each control character
// (control_chars.hpp), which could forge, hide or reorder a log or stderr
// line, becomes a space. client_ref will come from a Cloud job (C5.6).
std::string shown(std::string_view client_ref)
{
    std::string out;
    out.reserve(client_ref.size());
    for (std::size_t i = 0; i < client_ref.size();) {
        if (const std::size_t length = control_character_length(client_ref, i); length != 0) {
            out += ' ';
            i += length;
        } else {
            out += client_ref[i];
            ++i;
        }
    }
    return out;
}

connector::RestorePoint to_connector(const RestorePoint& point)
{
    connector::RestorePoint out;
    out.id = point.id;
    out.backup_time = point.backup_time;
    out.has_mail = point.is_exchange;
    out.has_sharepoint = point.is_sharepoint;
    out.has_onedrive = point.is_onedrive;
    out.is_archive = point.is_long_term_copy;
    return out;
}

bool is_set(const std::optional<std::string>& secret) noexcept
{
    return secret && !secret->empty();
}

} // namespace

VeeamM365Connector::VeeamM365Connector(std::unique_ptr<IHttpClient> http, std::string base_url,
                                       std::string username, std::string password,
                                       VeeamClientOptions options,
                                       std::shared_ptr<graph::GraphClient> graph,
                                       TargetGuardOptions guard_options)
    : http_(std::move(http)), graph_(std::move(graph)), guard_options_(std::move(guard_options))
{
    if (!http_) {
        throw std::invalid_argument("veeam_m365: no HTTP client");
    }
    client_ = std::make_unique<VeeamClient>(*http_, std::move(base_url), std::move(username),
                                            std::move(password), std::move(options));
}

VeeamM365Connector::~VeeamM365Connector()
{
    client_->logout();
}

connector::ConnectorInfo VeeamM365Connector::describe() const
{
    return {std::string{connector::kVeeamM365}, std::string{kApiVersion}};
}

std::vector<connector::RestorePoint> VeeamM365Connector::list_restore_points(
    const std::string& client_ref)
{
    if (client_ref.empty()) {
        throw std::invalid_argument("veeam_m365: the client reference is empty");
    }
    // VeeamError's what() went through rp::redact(), so it is passed on as it is.
    try {
        std::vector<Organization> matches;
        for (Organization& org : client_->list_organizations()) {
            if (ascii_iequals(org.name, client_ref)) {
                matches.push_back(std::move(org));
            }
        }
        if (matches.empty()) {
            throw connector::NotFoundError("client " + shown(client_ref) + " not found in Veeam");
        }
        if (matches.size() > 1) {
            throw connector::Error("client " + shown(client_ref) + " matches " +
                                   std::to_string(matches.size()) + " organisations in Veeam");
        }
        // VeeamClient would refuse it with std::invalid_argument; checked here
        // so that only this case reads as Veeam's fault.
        if (!is_uuid(matches.front().id)) {
            throw connector::Error("Veeam returned an organisation ID for client " +
                                   shown(client_ref) + " that isn't a UUID");
        }
        const std::vector<RestorePoint> points = client_->list_restore_points(matches.front().id);
        std::vector<connector::RestorePoint> out;
        out.reserve(points.size());
        std::ranges::transform(points, std::back_inserter(out), to_connector);
        return out;
    } catch (const AuthError& e) {
        throw connector::AuthError(e.what());
    } catch (const TransientError& e) {
        throw connector::TransientError(e.what());
    } catch (const NotFoundError& e) {
        throw connector::NotFoundError(e.what());
    } catch (const VeeamError& e) {
        throw connector::Error(e.what());
    }
}

connector::RestoreResult VeeamM365Connector::restore_sample(const connector::RestoreSpec& spec)
{
    // The guard is the first line (W2.7, #32): nothing reaches Veeam before
    // layer 1 passed. Its SafetyViolation passes out as it is: status `error`,
    // exit code 4, never `fail`.
    if (!graph_) {
        throw connector::Error(
            "veeam_m365: no Graph client, so the target guard can't run; nothing was restored");
    }
    std::optional<CheckedTargets> checked;
    try {
        checked.emplace(TargetGuard(*graph_, guard_options_).check_spec(spec));
    } catch (const graph::AuthError& e) {
        throw connector::AuthError(e.what());
    } catch (const graph::PermissionError& e) {
        throw connector::AuthError(e.what());
    } catch (const graph::TransientError& e) {
        throw connector::TransientError(e.what());
    } catch (const graph::NotFoundError& e) {
        throw connector::NotFoundError(e.what());
    } catch (const graph::GraphError& e) {
        throw connector::Error(e.what());
    }
    // TODO(W2.5), with `checked`:
    //  1. an empty spec returns not_run;
    //  2. browse (read-only calls) and build a veeam::RestoreRequestContext
    //     per source container (docs/api/veeam-restore-flow.md §4, §16);
    //  3. veeam::check_restore_request(*checked, ctx, path, body,
    //     guard_options_) on the exact path and text, immediately before each
    //     restore POST (rp/target_guard_veeam.hpp).
    throw connector::NotImplementedError(
        "veeam_m365: restore_sample is not implemented yet (W2.5)");
}

std::unique_ptr<connector::IConnector> make_veeam_m365_connector(
    const Config& config, const Secrets& secrets, const connector::ConnectorOptions& options)
{
    if (!is_set(secrets.veeam_username)) {
        throw ConfigError(std::string{kEnvVeeamUsername},
                          std::string{kEnvVeeamUsername} + " is not set");
    }
    if (!is_set(secrets.veeam_password)) {
        throw ConfigError(std::string{kEnvVeeamPassword},
                          std::string{kEnvVeeamPassword} + " is not set");
    }
    HttpClientOptions http_options;
    // TLS is never off: the CA file and the pin only choose what to trust.
    http_options.ca_file = config.veeam_ca_file;
    http_options.pinned_cert_sha256 = config.veeam_cert_sha256;
    http_options.logger = options.logger;
    http_options.sleep = options.sleep;
    http_options.jitter = options.jitter;
    std::unique_ptr<IHttpClient> http = options.make_http
                                            ? options.make_http(http_options)
                                            : std::make_unique<HttpClient>(http_options);

    VeeamClientOptions client_options;
    client_options.logger = options.logger;
    client_options.sleep = options.sleep;
    client_options.jitter = options.jitter;
    return std::make_unique<VeeamM365Connector>(std::move(http), config.veeam_url,
                                                *secrets.veeam_username, *secrets.veeam_password,
                                                std::move(client_options));
}

} // namespace rp
