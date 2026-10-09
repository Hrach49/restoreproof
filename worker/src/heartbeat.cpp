#include "heartbeat.hpp"

#include <rp/canonical_json.hpp>
#include <rp/uploader.hpp>

#include <nlohmann/json.hpp>

#include <format>
#include <utility>

namespace rp {

namespace {

using nlohmann::json;

bool is_status(int status) noexcept
{
    return status >= 100 && status <= 999;
}

std::string status_word(int status)
{
    return std::format("{}{}", heartbeat_code::kHttpPrefix, status);
}

std::string word_of(TransportError error)
{
    switch (error) {
    case TransportError::timeout:
        return std::string{heartbeat_code::kTimeout};
    case TransportError::connect:
    case TransportError::dropped:
    case TransportError::handshake:
    case TransportError::tls:
        return std::string{heartbeat_code::kUnreachable};
    default:
        return std::string{heartbeat_code::kInternal};
    }
}

} // namespace

std::string heartbeat_time_text(std::chrono::system_clock::time_point time)
{
    return std::format("{:%Y-%m-%dT%H:%M:%S}Z", std::chrono::floor<std::chrono::milliseconds>(time));
}

std::string heartbeat_body(const Heartbeat& heartbeat)
{
    json body{
        {"last_error", nullptr},
        {"last_error_at", nullptr},
        {"outbox_depth", heartbeat.outbox_depth},
        {"uptime_s", heartbeat.uptime_s},
        {"version", heartbeat.version},
    };
    if (heartbeat.last_error) {
        body["last_error"] = *heartbeat.last_error;
    }
    if (heartbeat.last_error_at) {
        body["last_error_at"] = heartbeat_time_text(*heartbeat.last_error_at);
    }
    return canonical_json(body);
}

HeartbeatAnswer send_heartbeat(IHttpClient& http, std::string_view cloud_url,
                               const Heartbeat& heartbeat)
{
    try {
        HttpRequest request;
        request.method = HttpMethod::post;
        request.url = cloud_endpoint(std::string{cloud_url}, kHeartbeatPath);
        request.body = heartbeat_body(heartbeat);
        request.content_type = "application/json";
        request.timeout = kHeartbeatTimeout;
        request.retry_on_status = false;
        request.max_attempts = 1;
        request.max_body_bytes = kMaxHeartbeatAnswerBytes;
        const HttpResponse response = http.send(request);
        if (response.status >= 200 && response.status <= 299) {
            return {true, {}};
        }
        if (!is_status(response.status)) {
            return {false, std::string{heartbeat_code::kInternal}};
        }
        return {false, status_word(response.status)};
    } catch (const HttpError& e) {
        // A 5xx never gets here (retry_on_status is off), but a client that
        // throws one all the same has its status.
        if (e.error() == TransportError::none && is_status(e.status())) {
            return {false, status_word(e.status())};
        }
        return {false, word_of(e.error())};
    } catch (...) {
        return {false, std::string{heartbeat_code::kInternal}};
    }
}

} // namespace rp
