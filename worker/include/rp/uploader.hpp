#pragma once

// The outbox's real uploader (W4.6, docs/decisions.md 2026-10-07 point 3):
// one POST of a run's files as multipart/form-data to <cloud_url>/v1/results,
// with the vault's API token as a bearer token (W5.1, docs/decisions.md
// 2026-10-15, point 8). What is sent is what rp::Outbox read and checked;
// nothing is decided here but which code an answer is: what a code does is
// the outbox's.

#include <rp/config.hpp>
#include <rp/http_client.hpp>
#include <rp/outbox.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace spdlog {
class logger;
}

namespace rp {

inline constexpr std::string_view kResultsPath = "/v1/results";
// The whole upload: connect, send and the answer.
inline constexpr std::chrono::milliseconds kUploadTimeout{120000};
// The most that is read of the answer's body.
inline constexpr std::uint64_t kMaxUploadAnswerBytes = 64u * 1024u;
// The one status that means the Cloud has the run.
inline constexpr int kUploadAccepted = 202;

// A Cloud route's URL: `cloud_url` (Config::cloud_url) with every '/' at its
// end dropped, then `path`, which starts with one ("/v1/results").
std::string cloud_endpoint(std::string cloud_url, std::string_view path);

class CloudUploader final : public IUploader {
public:
    // `http` must outlive the uploader. `cloud_url` is Config::cloud_url; a
    // '/' at its end is dropped. `token` is the vault's cloud_api_token.
    CloudUploader(IHttpClient& http, std::string cloud_url, std::string token);

    // POST <cloud_url>/v1/results with `Authorization: Bearer <token>` and one
    // multipart part per `parts`, in their order, each with its name, file
    // name, content type and bytes; sent once (max_attempts 1, no retry on a
    // status: the outbox owns the schedule), kUploadTimeout, redirects never
    // followed. 202 with X-RestoreProof-API: 1 is accepted. A 2xx without it,
    // or with another value, is upload_not_cloud (rp/cloud_api.hpp). Else:
    // upload_http_<status> for any other answer (three digits; a status
    // outside 100 to 999 is upload_internal), upload_timeout for a timeout,
    // upload_unreachable for no connection, a broken-off or failed TLS
    // handshake, a certificate the client refuses or a connection dropped
    // mid-request, upload_internal for anything else. Never throws.
    UploadAnswer upload(const std::string& run_id, const std::vector<UploadPart>& parts) override;

    // <cloud_url>/v1/results.
    const std::string& url() const noexcept { return url_; }

private:
    IHttpClient& http_;
    std::string url_;
    std::string token_;
};

// The HTTP client the Cloud is reached through: TLS verified against the
// Windows certificate store, or, with config's cloud_ca_file, against that
// PEM file in its place (the host name checked either way; nothing turns
// verification off). It logs to `logger`; null is the commands' logger,
// warnings and worse to stderr, which the service, having no stderr, replaces
// with its own (W4.8 point 12).
std::unique_ptr<IHttpClient>
make_cloud_http_client(const Config& config, std::shared_ptr<spdlog::logger> logger = nullptr);

} // namespace rp
