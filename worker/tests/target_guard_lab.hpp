#pragma once

// The restore-target guard (W2.7) as its tests see it: Graph served by a
// FakeHttpClient with the recorded replies for the test mailbox's Inbox, the
// RestoreTarget library and the test OneDrive folder (graph_lab.hpp), every
// log line in a string, and
// specs whose selectors name made-up sources outside the restore targets. No
// Catch2 assertions in here: FakeHttpClient's handlers may call these on the
// client's threads.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"

#include <rp/client_assertion.hpp>
#include <rp/connector.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_errors.hpp>
#include <rp/target_guard.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/ostream_sink.h>

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace rp::test::target_guard_lab {

using namespace rp::test::graph_lab;

// A source library's list ID. Made up.
inline const std::string kMadeUpListId = "0b5e1d2c-0000-4000-8000-00000000c0de";

// Sources a sample may take, never a restore target. Made up, never a lab value.
inline rp::connector::MailSelector mail_source(int n = 1)
{
    return {"alice@RestoreProofLab.onmicrosoft.com", "Inbox", "subject " + std::to_string(n)};
}
inline rp::connector::SharePointSelector sharepoint_source(int n = 1)
{
    return {lab_values().site_id, "b!madeUpSourceLibraryDrive", "/",
            "file-" + std::to_string(n) + ".pdf", kMadeUpListId};
}
inline rp::connector::OneDriveSelector onedrive_source(int n = 1)
{
    return {"alice@RestoreProofLab.onmicrosoft.com", "/RestoreTest",
            "file-" + std::to_string(n) + ".pdf"};
}

// A spec on the lab's targets with the given items.
inline rp::connector::RestoreSpec make_spec(std::vector<rp::connector::MailSelector> mail = {},
                                            std::vector<rp::connector::SharePointSelector> sp = {},
                                            std::vector<rp::connector::OneDriveSelector> od = {},
                                            const rp::Config& config = lab_config())
{
    return {"RestoreProofLab.onmicrosoft.com", {},
            rp::connector::RestoreTargets::from_config(config), std::move(mail), std::move(sp),
            std::move(od)};
}

// One item of each type.
inline rp::connector::RestoreSpec full_spec()
{
    return make_spec({mail_source()}, {sharepoint_source()}, {onedrive_source()});
}

// A logger writing "<level> <message>" lines to `stream`.
inline std::shared_ptr<spdlog::logger> string_logger(const std::string& name,
                                                     std::ostringstream& stream)
{
    auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(stream);
    auto logger = std::make_shared<spdlog::logger>(name, sink);
    logger->set_level(spdlog::level::trace);
    logger->set_formatter(std::make_unique<spdlog::pattern_formatter>(
        "%l %v", spdlog::pattern_time_type::utc, "\n"));
    return logger;
}

struct GuardLab {
    GuardLab()
    {
        logger = string_logger("target_guard_test", log_stream);
        graph_logger = string_logger("target_guard_graph", graph_log_stream);
        graph_http.on(HttpMethod::post, kTokenUrl, {token_response()});
        serve(inbox_url(), load_fixture_json("graph", "mailbox-inbox-200"));
        serve(drive_url(), load_fixture_json("graph", "restoretarget-drive-200"));
        serve(folder_url(), load_fixture_json("graph", "onedrive-folder-200"));
        rp::graph::GraphClientOptions options;
        options.logger = graph_logger;
        options.now = [] { return std::chrono::steady_clock::time_point{}; };
        options.wall_now = [] { return kNow; };
        options.sleep = [](std::chrono::milliseconds) {};
        options.jitter = [] { return 0.0; };
        graph = std::make_shared<rp::graph::GraphClient>(
            graph_http, kTenant, kClient,
            rp::graph::load_client_certificate(pfx_base64(), kPfxPassword, kNow), options);
    }

    rp::TargetGuardOptions options() const { return {logger}; }

    rp::TargetGuard guard() { return rp::TargetGuard(*graph, options()); }

    // A target's recorded reply, edited by `edit` (on its body).
    void serve_edited(const std::string& url, const std::string& fixture,
                      const std::function<void(nlohmann::json&)>& edit)
    {
        nlohmann::json recorded = load_fixture_json("graph", fixture);
        edit(recorded["body"]);
        serve(url, recorded);
    }

    void serve(const std::string& url, const nlohmann::json& fixture)
    {
        graph_http.on(HttpMethod::get, url, {to_response(fixture)});
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    // Every request Graph got other than token requests.
    std::size_t graph_gets() const
    {
        std::size_t n = 0;
        for (const HttpRequest& request : graph_http.requests()) {
            n += request.url != kTokenUrl ? 1 : 0;
        }
        return n;
    }

    std::size_t gets(const std::string& url) const { return graph_http.count(HttpMethod::get, url); }

    // The guard's lines only; GraphClient's go to graph_log_stream.
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
    std::ostringstream graph_log_stream;
    std::shared_ptr<spdlog::logger> graph_logger;
    FakeHttpClient graph_http;
    std::shared_ptr<rp::graph::GraphClient> graph;
};

// What a call threw: its kind and message.
struct Thrown {
    std::string kind = "none";
    std::string what;
};

inline Thrown thrown_by(const std::function<void()>& call)
{
    try {
        call();
    } catch (const rp::connector::SafetyViolation& e) {
        return {"SafetyViolation", e.what()};
    } catch (const rp::graph::PermissionError& e) {
        return {"PermissionError", e.what()};
    } catch (const rp::graph::NotFoundError& e) {
        return {"NotFoundError", e.what()};
    } catch (const rp::graph::TransientError& e) {
        return {"TransientError", e.what()};
    } catch (const rp::graph::AuthError& e) {
        return {"AuthError", e.what()};
    } catch (const rp::graph::GraphError& e) {
        return {"GraphError", e.what()};
    } catch (const std::exception& e) {
        return {"other", e.what()};
    }
    return {};
}

} // namespace rp::test::target_guard_lab
