#include <rp/uploader.hpp>

#include "command_config.hpp"

#include <format>
#include <utility>

namespace rp {

namespace {

std::string results_url(std::string cloud_url)
{
    while (cloud_url.ends_with('/')) {
        cloud_url.pop_back();
    }
    return cloud_url + std::string{kResultsPath};
}

std::string code_of(TransportError error)
{
    switch (error) {
    case TransportError::timeout:
        return std::string{upload_code::kTimeout};
    case TransportError::connect:
    case TransportError::dropped:
    case TransportError::handshake:
    case TransportError::tls:
        return std::string{upload_code::kUnreachable};
    default:
        return std::string{upload_code::kInternal};
    }
}

} // namespace

CloudUploader::CloudUploader(IHttpClient& http, std::string cloud_url)
    : http_(http), url_(results_url(std::move(cloud_url)))
{
}

UploadAnswer CloudUploader::upload(const std::string&, const std::vector<UploadPart>& parts)
{
    try {
        HttpRequest request;
        request.method = HttpMethod::post;
        request.url = url_;
        for (const UploadPart& part : parts) {
            request.parts.push_back({part.name, part.bytes, part.filename, part.content_type});
        }
        request.timeout = kUploadTimeout;
        request.retry_on_status = false;
        request.max_attempts = 1;
        request.max_body_bytes = kMaxUploadAnswerBytes;
        const HttpResponse response = http_.send(request);
        if (response.status == kUploadAccepted) {
            return {true, {}};
        }
        if (response.status < 100 || response.status > 999) {
            return {false, std::string{upload_code::kInternal}};
        }
        return {false, std::format("{}{}", upload_code::kHttpPrefix, response.status)};
    } catch (const HttpError& e) {
        // A 5xx never gets here (retry_on_status is off), but a client that
        // throws one all the same has its status.
        if (e.error() == TransportError::none && e.status() >= 100 && e.status() <= 999) {
            return {false, std::format("{}{}", upload_code::kHttpPrefix, e.status())};
        }
        return {false, code_of(e.error())};
    } catch (...) {
        return {false, std::string{upload_code::kInternal}};
    }
}

std::unique_ptr<IHttpClient> make_cloud_http_client(const Config& config)
{
    HttpClientOptions options;
    options.ca_file = config.cloud_ca_file;
    options.logger = make_command_logger();
    return std::make_unique<HttpClient>(std::move(options));
}

} // namespace rp
