#pragma once

// One request sent once, its failure as a word (W5.1, docs/decisions.md
// 2026-10-15, points 2 and 7): what `cloud register` and the service's poll
// send through. Not strict: the one HTTP call and the catch around it, as
// src/uploader.cpp and src/heartbeat.cpp are; what an answer means is the
// callers'.

#include <rp/http_client.hpp>

#include <optional>
#include <string>

namespace rp {

// The exchange's words beside a status.
namespace exchange_word {
inline constexpr std::string_view kUnreachable = "unreachable";
inline constexpr std::string_view kTimeout = "timeout";
inline constexpr std::string_view kInternal = "internal";
} // namespace exchange_word

struct Exchange {
    // The answer, when one came: a status of 100 to 999 (a client that
    // throws one has it here, with no headers and no body).
    std::optional<HttpResponse> response;
    // Empty with an answer; else timeout, unreachable (no connection, a
    // broken-off or failed TLS handshake, a certificate the client refuses, a
    // connection dropped mid-request) or internal (anything else, a status
    // outside 100 to 999 included).
    std::string word;
};

// `http.send(request)`. Never throws but for no memory.
Exchange exchange(IHttpClient& http, const HttpRequest& request);

} // namespace rp
