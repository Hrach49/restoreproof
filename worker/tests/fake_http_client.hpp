#pragma once

// An IHttpClient that answers from fixtures instead of the network (W1.5,
// Q2.1). Routes match on the method and, in this order, the whole URL, query
// included (on); the URL's path and query, scheme and host ignored, as a
// recording's request line holds them (serve_recording); or a path pattern
// (on_path). It never retries: each send() is one answer, so tests count
// exactly what the code under test sent.
//
// Fixtures live in tests/fixtures/<service>/<name>.json (format in
// tests/fixtures/veeam/README.md): {"status", "headers", "body"}, where a null
// body is empty, a string is raw text and anything else is JSON. `rpworker
// ... --record <dir>` writes the same format (rp/recording_http_client.hpp).

#include <rp/base64.hpp>
#include <rp/http_client.hpp>
#include <rp/recording_http_client.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp::test {

// The fixture file as JSON. Throws std::runtime_error if it can't be read.
// No Catch2 assertions in here or in anything a handler may call: handlers run
// on the client's threads, and Catch2's assertions are for the test's thread
// only.
inline nlohmann::json load_fixture_json(std::string_view service, std::string_view name)
{
    const std::string path =
        std::string{RP_FIXTURE_DIR} + "/" + std::string{service} + "/" + std::string{name} + ".json";
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot read fixture " + path);
    }
    return nlohmann::json::parse(std::string{std::istreambuf_iterator<char>(file), {}});
}

// The bytes of a fixture's Base64 text. Throws std::runtime_error for text
// that isn't strict Base64.
inline std::string fixture_bytes(const std::string& base64)
{
    const std::optional<std::vector<unsigned char>> bytes = base64_decode(base64);
    if (!bytes) {
        throw std::runtime_error("the fixture's Base64 can't be decoded");
    }
    return std::string(bytes->begin(), bytes->end());
}

// A fixture (as load_fixture_json gives it, perhaps edited) as a response.
// Throws std::runtime_error for a recorded one that holds only its body's size
// and SHA-256 (a download's): there are no bytes to send.
template <typename Json>
HttpResponse to_response(const Json& fixture)
{
    if (fixture.contains("body_sha256")) {
        throw std::runtime_error("the fixture records only its body's size and SHA-256");
    }
    HttpResponse response;
    response.status = fixture.at("status").template get<int>();
    for (const auto& [name, value] : fixture.at("headers").items()) {
        response.headers[name] = value.template get<std::string>();
    }
    const auto& body = fixture.at("body");
    response.body = body.is_null()     ? ""
                    : body.is_string() ? body.template get<std::string>()
                                       : body.dump();
    // A binary body (W4.4, a TSA's answer): "body" null and the bytes in
    // "body_base64".
    if (fixture.contains("body_base64")) {
        response.body = fixture_bytes(fixture.at("body_base64").template get<std::string>());
    }
    return response;
}

// The request body a binary fixture recorded ("request_body_base64": a
// timestamp query, a hash and a nonce), or empty when it holds none.
template <typename Json>
std::string request_body_of(const Json& fixture)
{
    return fixture.contains("request_body_base64")
               ? fixture_bytes(fixture.at("request_body_base64").template get<std::string>())
               : std::string{};
}

inline HttpResponse load_fixture(std::string_view service, std::string_view name)
{
    return to_response(load_fixture_json(service, name));
}

// A response of the Cloud's app (W5.1): `make_response` with the contract
// header X-RestoreProof-API: 1, which the Worker reads on every 2xx.
inline HttpResponse cloud_answer(int status, std::string body = {},
                                 std::string content_type = "application/json");

// A response made up in a test.
inline HttpResponse make_response(int status, std::string body = {},
                                  std::string content_type = "application/json; charset=utf-8")
{
    HttpResponse response;
    response.status = status;
    if (!body.empty()) {
        response.headers["Content-Type"] = std::move(content_type);
    }
    response.body = std::move(body);
    return response;
}

inline HttpResponse cloud_answer(int status, std::string body, std::string content_type)
{
    HttpResponse response = make_response(status, std::move(body), std::move(content_type));
    response.headers["X-RestoreProof-API"] = "1";
    return response;
}

// The number a recorded file's name starts with ("1000-get-....json"); the
// largest number there is for a name that starts with none.
inline std::size_t recorded_file_number(const std::filesystem::path& file)
{
    const std::string name = file.filename().string();
    std::size_t n = 0;
    std::size_t digits = 0;
    for (; digits < name.size() && name[digits] >= '0' && name[digits] <= '9'; ++digits) {
        n = n * 10 + static_cast<std::size_t>(name[digits] - '0');
    }
    return digits == 0 ? std::numeric_limits<std::size_t>::max() : n;
}

// Whether `path` matches `pattern`, in which '*' stands for any run of
// characters, none of them '/'; every other character matches only itself.
inline bool path_matches(std::string_view pattern, std::string_view path)
{
    if (pattern.empty()) {
        return path.empty();
    }
    if (pattern.front() == '*') {
        for (std::size_t n = 0;; ++n) {
            if (path_matches(pattern.substr(1), path.substr(n))) {
                return true;
            }
            if (n == path.size() || path[n] == '/') {
                return false;
            }
        }
    }
    return !path.empty() && pattern.front() == path.front() &&
           path_matches(pattern.substr(1), path.substr(1));
}

class FakeHttpClient final : public IHttpClient {
public:
    using Handler = std::function<HttpResponse(const HttpRequest&)>;

    // Answers `method` `url` with whatever `handler` returns (or throws). The
    // handler runs outside the fake's lock, so it may block or call back in.
    void on(HttpMethod method, std::string url, Handler handler)
    {
        const std::lock_guard lock(mutex_);
        routes_[{method, std::move(url)}] = std::move(handler);
    }

    // Answers with `responses` in turn; the last one repeats.
    void on(HttpMethod method, std::string url, std::vector<HttpResponse> responses)
    {
        on(method, std::move(url), in_turn(std::move(responses)));
    }

    // Answers `method` and any URL whose path and query (rp::request_path) match
    // `pattern` (path_matches), when no route of `on` or serve_recording
    // does. The first pattern added that matches wins.
    void on_path(HttpMethod method, std::string pattern, Handler handler)
    {
        const std::lock_guard lock(mutex_);
        patterns_.push_back({method, std::move(pattern), std::move(handler)});
    }

    // Answers with `responses` in turn; the last one repeats.
    void on_path(HttpMethod method, std::string pattern, std::vector<HttpResponse> responses)
    {
        on_path(method, std::move(pattern), in_turn(std::move(responses)));
    }

    // Serves every *.json in `dir`, a recording's service folder (`rpworker
    // ... --record <dir>` writes <dir>/<service>/): each by the method and the
    // path and query of its "request" line, whatever the URL's host
    // (rp::request_path, the recorder's own rule). The files of one request
    // answer in turn in the order of their numbers (1000 after 999, whatever
    // the names' order), the last one repeating. A file holding only its body's digest throws when it is
    // served (to_response). Returns how many files it loaded. Throws for a
    // folder that can't be read, a file that isn't JSON, and
    // std::runtime_error for a request line without a method it knows and a
    // path.
    std::size_t serve_recording(const std::filesystem::path& dir)
    {
        std::vector<std::filesystem::path> files;
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                files.push_back(entry.path());
            }
        }
        std::ranges::sort(files, {}, [](const std::filesystem::path& file) {
            return std::pair{recorded_file_number(file), file};
        });
        std::map<std::pair<HttpMethod, std::string>, std::vector<nlohmann::ordered_json>>
            by_request;
        for (const std::filesystem::path& path : files) {
            std::ifstream file(path, std::ios::binary);
            nlohmann::ordered_json fixture = nlohmann::ordered_json::parse(
                std::string{std::istreambuf_iterator<char>(file), {}});
            const std::string line = fixture.at("request").get<std::string>();
            const std::size_t space = line.find(' ');
            if (space == std::string::npos) {
                throw std::runtime_error("no path in the request line of " + path.string());
            }
            by_request[{method_named(line.substr(0, space), path), line.substr(space + 1)}]
                .push_back(std::move(fixture));
        }
        const std::lock_guard lock(mutex_);
        for (auto& [key, fixtures] : by_request) {
            auto state =
                std::make_shared<std::pair<std::mutex, std::vector<nlohmann::ordered_json>>>();
            state->second = std::move(fixtures);
            auto next = std::make_shared<std::size_t>(0);
            path_routes_[key] = [state, next](const HttpRequest&) {
                nlohmann::ordered_json fixture;
                {
                    const std::lock_guard lock(state->first);
                    fixture = state->second[std::min(*next, state->second.size() - 1)];
                    ++*next;
                }
                return to_response(fixture);
            };
        }
        return files.size();
    }

    HttpResponse send(const HttpRequest& request) override
    {
        Handler handler;
        {
            const std::lock_guard lock(mutex_);
            requests_.push_back(request);
            handler = route(request);
            if (!handler) {
                throw std::logic_error("FakeHttpClient: no route for " +
                                       std::string{to_string(request.method)} + " " + request.url);
            }
        }
        return handler(request);
    }

    // Every request sent so far, in order.
    std::vector<HttpRequest> requests() const
    {
        const std::lock_guard lock(mutex_);
        return requests_;
    }

    // How many requests went to `method` `url`.
    std::size_t count(HttpMethod method, std::string_view url) const
    {
        const std::lock_guard lock(mutex_);
        std::size_t n = 0;
        for (const HttpRequest& request : requests_) {
            n += request.method == method && request.url == url ? 1 : 0;
        }
        return n;
    }

private:
    struct PathPattern {
        HttpMethod method;
        std::string pattern;
        Handler handler;
    };

    // A handler answering with `responses` in turn, the last one repeating.
    static Handler in_turn(std::vector<HttpResponse> responses)
    {
        REQUIRE_FALSE(responses.empty());
        auto state = std::make_shared<std::pair<std::mutex, std::vector<HttpResponse>>>();
        state->second = std::move(responses);
        auto next = std::make_shared<std::size_t>(0);
        return [state, next](const HttpRequest&) {
            const std::lock_guard lock(state->first);
            const std::size_t at = std::min(*next, state->second.size() - 1);
            ++*next;
            return state->second[at];
        };
    }

    static HttpMethod method_named(const std::string& verb, const std::filesystem::path& file)
    {
        if (verb == "GET") {
            return HttpMethod::get;
        }
        if (verb == "POST") {
            return HttpMethod::post;
        }
        if (verb == "DELETE") {
            return HttpMethod::del;
        }
        throw std::runtime_error("no method in the request line of " + file.string());
    }

    // The handler for `request`, or null. Called under the lock.
    Handler route(const HttpRequest& request) const
    {
        if (const auto it = routes_.find({request.method, request.url}); it != routes_.end()) {
            return it->second;
        }
        const std::string path{request_path(request.url)};
        if (const auto it = path_routes_.find({request.method, path}); it != path_routes_.end()) {
            return it->second;
        }
        for (const PathPattern& p : patterns_) {
            if (p.method == request.method && path_matches(p.pattern, path)) {
                return p.handler;
            }
        }
        return nullptr;
    }

    mutable std::mutex mutex_;
    std::map<std::pair<HttpMethod, std::string>, Handler> routes_;
    std::map<std::pair<HttpMethod, std::string>, Handler> path_routes_;
    std::vector<PathPattern> patterns_;
    std::vector<HttpRequest> requests_;
};

// An IHttpClient the code under test owns that sends through a fake the test
// keeps, so the test can still read the fake's log after that code (and the
// client) are gone.
class ForwardingHttpClient final : public IHttpClient {
public:
    explicit ForwardingHttpClient(IHttpClient& target) : target_(target) {}

    HttpResponse send(const HttpRequest& request) override { return target_.send(request); }

private:
    IHttpClient& target_;
};

} // namespace rp::test
