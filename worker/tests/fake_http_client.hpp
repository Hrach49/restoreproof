#pragma once

// An IHttpClient that answers from fixtures instead of the network: the part
// of Q2.1's FakeHttpClient that W1.5 needs. Routes match on method and the
// whole URL, query included. It never retries: each send() is one answer, so
// tests count exactly what the code under test sent.
//
// Fixtures live in tests/fixtures/<service>/<name>.json (format in
// tests/fixtures/veeam/README.md): {"status", "headers", "body"}, where a null
// body is empty, a string is raw text and anything else is JSON.

#include <rp/http_client.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
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

// A fixture (as load_fixture_json gives it, perhaps edited) as a response.
inline HttpResponse to_response(const nlohmann::json& fixture)
{
    HttpResponse response;
    response.status = fixture.at("status").get<int>();
    for (const auto& [name, value] : fixture.at("headers").items()) {
        response.headers[name] = value.get<std::string>();
    }
    const nlohmann::json& body = fixture.at("body");
    response.body = body.is_null() ? "" : body.is_string() ? body.get<std::string>() : body.dump();
    return response;
}

inline HttpResponse load_fixture(std::string_view service, std::string_view name)
{
    return to_response(load_fixture_json(service, name));
}

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
        REQUIRE_FALSE(responses.empty());
        auto state = std::make_shared<std::pair<std::mutex, std::vector<HttpResponse>>>();
        state->second = std::move(responses);
        auto next = std::make_shared<std::size_t>(0);
        on(method, std::move(url), [state, next](const HttpRequest&) {
            const std::lock_guard lock(state->first);
            const std::size_t at = std::min(*next, state->second.size() - 1);
            ++*next;
            return state->second[at];
        });
    }

    HttpResponse send(const HttpRequest& request) override
    {
        Handler handler;
        {
            const std::lock_guard lock(mutex_);
            requests_.push_back(request);
            const auto it = routes_.find({request.method, request.url});
            if (it == routes_.end()) {
                throw std::logic_error("FakeHttpClient: no route for " +
                                       std::string{to_string(request.method)} + " " + request.url);
            }
            handler = it->second;
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
    mutable std::mutex mutex_;
    std::map<std::pair<HttpMethod, std::string>, Handler> routes_;
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
