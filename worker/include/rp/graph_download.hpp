#pragma once

// Downloading a file's bytes from SharePoint or OneDrive (W2.2). Graph answers
// GET .../items/{id}/content with a redirect to a short-lived download link on
// the tenant's SharePoint, a link that carries its own credential (tempauth).
// That redirect is followed WITHOUT the Graph token, through an HttpClient of
// its own that logs nothing, and only to the test tenant's SharePoint over
// https (docs/decisions.md, W2.1 §6 and W2.2). The file is read whole into
// memory, capped at the size Graph lists for it.

#include <rp/graph_client.hpp>
#include <rp/http_client.hpp>

#include <spdlog/logger.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace rp::graph {

// The largest file the Worker downloads (whole, in memory). The canaries are < 30 KB.
inline constexpr std::uint64_t kMaxDownloadBytes = 64ull * 1024 * 1024;

struct DownloadOptions {
    std::uint64_t max_bytes = kMaxDownloadBytes;                  // must be above 0
    std::chrono::milliseconds timeout{std::chrono::seconds{120}}; // per request, above 0
    std::shared_ptr<spdlog::logger> logger;                       // null: spdlog default
};

// The HttpClient for downloads: make_graph_http_client()'s options (the
// Windows store, full verification, no CA file, no pin) with a logger whose
// only sink is a null sink, so the download URL, which carries a credential,
// is never logged by HttpClient whatever redact() knows. A separate instance
// from GraphClient's, so no state is shared.
std::unique_ptr<IHttpClient> make_download_http_client();

// nullopt when `url` may be fetched without a token, else why not (never
// quoting the URL). `tenant_host` is the host of test_site_id,
// "<t>.sharepoint.com". Accepted: "https://" (scheme in any case) + host +
// optional ":443" + a path starting '/', the host (any case) being exactly
// `tenant_host` or "<t>-my.sharepoint.com". Refused: another scheme, a
// relative URL, user info ('@' in the authority), any other port, whitespace,
// a control character, a backslash or '#' anywhere, any other host.
std::optional<std::string> download_url_problem(std::string_view url, std::string_view tenant_host);

// GET <drive>/items/<item>/content through `graph` (with the token), then the
// bytes from the redirect's Location through `download` (WITHOUT the token).
// `what` names the item in messages ("the RestoreTarget library item 01AB...");
// `expected_size` is Graph's `size`. Returns exactly expected_size bytes, else
// throws: std::invalid_argument for bad `options` (nothing sent), whatever
// graph.get() throws as it is, and otherwise a GraphError or, for what may
// work later (a lost connection, a timeout, 5xx retries used up, a 429), a
// TransientError. The Location is never in a message or a log line. The
// request to `download` carries only User-Agent: user_agent() and Accept: */*;
// never a header from Graph's reply.
std::string download_item(GraphClient& graph, IHttpClient& download, const Grant& grant,
                          std::string_view tenant_host, std::string_view drive_id,
                          std::string_view item_id, std::uint64_t expected_size,
                          std::string_view what, const DownloadOptions& options = {});

} // namespace rp::graph
