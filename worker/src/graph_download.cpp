#include <rp/graph_download.hpp>

#include <rp/config.hpp>
#include <rp/redact.hpp>
#include <rp/retry_policy.hpp>

#include "text_util.hpp"

#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <utility>

namespace rp::graph {

namespace {

// A URI scheme: a letter, then letters, digits, '+', '-' or '.'.
bool is_scheme(std::string_view text)
{
    return !text.empty() && std::isalpha(static_cast<unsigned char>(text.front())) &&
           std::all_of(text.begin(), text.end(), [](unsigned char c) {
               return std::isalnum(c) || c == '+' || c == '-' || c == '.';
           });
}

bool has_bad_character(std::string_view url)
{
    for (std::size_t i = 0; i < url.size(); ++i) {
        const char c = url[i];
        if (c == ' ' || c == '\\' || c == '#' || control_character_length(url, i) != 0) {
            return true;
        }
    }
    return false;
}

// The authority of an "https://" URL that passed download_url_problem, without the port.
std::string host_of(std::string_view url)
{
    const std::string_view authority = url.substr(8, url.find('/', 8) - 8);
    return std::string{authority.substr(0, authority.find(':'))};
}

void log_debug(const DownloadOptions& options, const std::string& line)
{
    // May be null: spdlog::drop_all() and shutdown() clear the default logger.
    const std::shared_ptr<spdlog::logger> logger =
        options.logger ? options.logger : spdlog::default_logger();
    if (logger && logger->should_log(spdlog::level::debug)) {
        logger->debug("{}", redact(line));
    }
}

bool is_followed_redirect(int status)
{
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

// The bytes, if exactly `expected_size` came; else why not.
std::string checked_size(std::string body, std::uint64_t expected_size, std::string_view what)
{
    if (body.size() > expected_size) {
        throw GraphError("SharePoint sent more than the " + std::to_string(expected_size) +
                         " bytes Graph lists for " + std::string{what} + "; nothing was hashed");
    }
    if (body.size() < expected_size) {
        throw GraphError("SharePoint sent " + std::to_string(body.size()) + " bytes for " +
                         std::string{what} + ", Graph lists " + std::to_string(expected_size) +
                         "; nothing was hashed");
    }
    return body;
}

// The bytes, if no more than `limit` came; else why not.
std::string checked_limit(std::string body, std::uint64_t limit, std::string_view what)
{
    if (body.size() > limit) {
        throw GraphError("SharePoint sent more than the " + std::to_string(limit) +
                         " byte download limit for " + std::string{what} + "; nothing was hashed");
    }
    return body;
}

// GET `location` through `download`, without the token; the reply's status mapped.
HttpResponse fetch(IHttpClient& download, const std::string& location, std::uint64_t cap,
                   std::string_view what, const DownloadOptions& options)
{
    HttpRequest request;
    request.method = HttpMethod::get;
    request.url = location;
    request.headers["User-Agent"] = user_agent();
    request.headers["Accept"] = "*/*";
    request.retry_on_status = true;
    request.timeout = options.timeout;
    request.max_body_bytes = cap;
    const std::string item{what};
    HttpResponse response;
    try {
        response = download.send(request);
    } catch (const HttpError& e) {
        // Never quoted: its message holds the URL. HttpClient retried what
        // is_retryable() takes, so that is what may work later.
        if (is_retryable(AttemptOutcome{e.error(), e.status()})) {
            throw TransientError("the download of " + item + " failed after " +
                                     std::to_string(e.attempts()) + " attempt(s)",
                                 e.status());
        }
        if (e.error() == TransportError::none) {
            throw GraphError("SharePoint answered " + std::to_string(e.status()) +
                                 " to the download of " + item,
                             e.status());
        }
        if (e.error() == TransportError::tls) {
            throw GraphError("the download of " + item +
                                 " failed: SharePoint's certificate was not trusted, or TLS could "
                                 "not be set up",
                             e.status());
        }
        throw GraphError("the download of " + item +
                             " failed and was not retried: SharePoint's reply was malformed, or "
                             "the request failed on this machine",
                         e.status());
    }
    const int status = response.status;
    const std::string code = std::to_string(status);
    if (status >= 300 && status <= 399) {
        throw GraphError("SharePoint redirected the download of " + item + " again (" + code +
                             "); nothing was downloaded",
                         status);
    }
    if (status == 401 || status == 403) {
        throw GraphError("SharePoint refused the download of " + item + " (" + code +
                             "); the link Graph gave may have expired",
                         status);
    }
    if (status == 404) {
        throw GraphError("SharePoint has no content for " + item +
                             " (404); it may have been removed while the Worker read it",
                         status);
    }
    // HttpClient retries a 5xx itself; one returned all the same is as transient.
    if (status == 429 || (status >= 500 && status <= 599)) {
        throw TransientError("the download of " + item + " failed: SharePoint answered " + code,
                             status);
    }
    if (status != 200) {
        throw GraphError("SharePoint answered " + code + " to the download of " + item, status);
    }
    return response;
}

} // namespace

std::unique_ptr<IHttpClient>
make_download_http_client(std::function<void(std::chrono::milliseconds)> sleep)
{
    HttpClientOptions options = graph_http_client_options(std::make_shared<spdlog::logger>(
        "rp-download", std::make_shared<spdlog::sinks::null_sink_mt>()));
    options.sleep = std::move(sleep);
    return std::make_unique<HttpClient>(std::move(options));
}

std::optional<std::string> download_url_problem(std::string_view url, std::string_view tenant_host)
{
    if (has_bad_character(url)) {
        return "it holds whitespace, a control character, a backslash or '#'";
    }
    const std::size_t separator = url.find("://");
    if (separator == std::string_view::npos || !is_scheme(url.substr(0, separator))) {
        return "not an absolute URL";
    }
    if (ascii_lower(url.substr(0, separator)) != "https") {
        return "not https";
    }
    const std::size_t start = separator + 3;
    const std::size_t end = std::min(url.find('/', start), url.find('?', start));
    if (end == std::string_view::npos || url[end] != '/') {
        return "not an absolute URL";
    }
    const std::string_view authority = url.substr(start, end - start);
    const std::size_t colon = authority.find(':');
    if (authority.find('@') != std::string_view::npos ||
        (colon != std::string_view::npos && authority.substr(colon + 1) != "443")) {
        return "it has user info or a port other than 443";
    }
    const std::string host = ascii_lower(authority.substr(0, colon));
    const std::string tenant = ascii_lower(tenant_host);
    const std::optional<std::string> onedrive = onedrive_host(tenant);
    if (!onedrive || (host != tenant && host != *onedrive)) {
        return "its host is not the test tenant's SharePoint";
    }
    return std::nullopt;
}

std::string download_item(GraphClient& graph, IHttpClient& download, const Grant& grant,
                          std::string_view tenant_host, std::string_view drive_id,
                          std::string_view item_id, std::uint64_t expected_size,
                          SizeCheck size_check, std::string_view what,
                          const DownloadOptions& options)
{
    if (options.max_bytes == 0 || options.timeout <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument("download options: max_bytes and timeout must be above 0");
    }
    const std::string item{what};
    if (expected_size > options.max_bytes) {
        throw GraphError(item + " is " + std::to_string(expected_size) + " bytes, over the " +
                         std::to_string(options.max_bytes) +
                         " byte download limit; nothing was downloaded");
    }
    const bool exact = size_check == SizeCheck::exact;
    const std::uint64_t cap = exact ? expected_size : options.max_bytes;
    HttpResponse content = graph.get(
        "/drives/" + std::string{drive_id} + "/items/" + std::string{item_id} + "/content", grant,
        {}, cap);
    const int status = content.status;
    HttpResponse response;
    if (status == 200) {
        response = std::move(content);
    } else if (status < 300) {
        throw GraphError("Graph answered " + std::to_string(status) +
                             " to the content request for " + item +
                             ", neither the file nor a redirect",
                         status);
    } else if (!is_followed_redirect(status)) {
        throw GraphError("Graph answered " + std::to_string(status) +
                             " to the content request for " + item +
                             ", not a redirect the Worker follows",
                         status);
    } else {
        const auto found = content.headers.find("Location");
        if (found == content.headers.end() || found->second.empty()) {
            throw GraphError("Graph's redirect for " + item +
                                 " has no Location; nothing was downloaded",
                             status);
        }
        const std::string& location = found->second;
        if (const std::optional<std::string> problem = download_url_problem(location, tenant_host)) {
            throw GraphError("Graph's redirect for " + item +
                                 " is not an https URL on the test tenant's SharePoint (" +
                                 *problem + "); nothing was downloaded",
                             status);
        }
        log_debug(options, "download of " + item + ": following Graph's redirect to " +
                               host_of(location));
        response = fetch(download, location, cap, item, options);
    }
    std::string line = "download of " + item + ": " + std::to_string(response.status) + ", " +
                       std::to_string(response.body.size()) + " bytes";
    if (response.body.size() != expected_size) {
        line += "; Graph lists " + std::to_string(expected_size);
    }
    log_debug(options, line);
    return exact ? checked_size(std::move(response.body), expected_size, item)
                 : checked_limit(std::move(response.body), cap, item);
}

} // namespace rp::graph
