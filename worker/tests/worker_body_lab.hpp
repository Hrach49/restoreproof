#pragma once

// The service's body on the restore tests' Harness (W4.8): rp::test::
// worker_body_lab::BodyLab runs rp::make_worker_loop_env's real env (the
// pipeline in process, the record's and the outbox's real file calls, the
// close, the uploader and the heartbeat) with a fake Cloud, fake locks, a
// wait that costs no time and, when a test asks, the hold's fake connector;
// worker_body_test.cpp's tests and the W4.9 secret audit run on it. No test
// on it waits, starts the service, reads the vault or touches %ProgramData%.
// No Catch2 assertion in a fake's handler.

#include "../src/worker_body.hpp"

#include "../src/file_read.hpp"

#include "restore_command_lab.hpp"

#include <rp/client_profile.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/outbox.hpp>
#include <rp/service.hpp>
#include <rp/service_loop.hpp>
#include <rp/service_recovery.hpp>
#include <rp/signer.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace rp::test::worker_body_lab {

using namespace rp::test::restore_command_lab;
using std::chrono::milliseconds;

const std::string kResultsUrl = "https://cloud.example.invalid/v1/results";
const std::string kHeartbeatUrl = "https://cloud.example.invalid/v1/heartbeat";
const std::string kSessionA = "aaaaaaaa-0000-4000-8000-000000000001";
const std::string kSessionB = "aaaaaaaa-0000-4000-8000-000000000002";

// What the hold's connector answers (point 9): the sessions still running,
// which an end takes away.
struct HoldFake {
    std::vector<connector::OwnSession> running;
    std::function<void()> look_throw;
    int made = 0;
    int looks = 0;
    std::vector<std::string> ended;
    std::optional<rp::Secrets> secrets;
    std::optional<std::chrono::system_clock::time_point> since;
};

class HoldConnector final : public connector::IConnector {
public:
    explicit HoldConnector(HoldFake& fake) : fake_(fake) {}

    connector::ConnectorInfo describe() const override
    {
        return {std::string{connector::kVeeamM365}, "1"};
    }
    std::vector<connector::RestorePoint> list_restore_points(const std::string&) override
    {
        throw std::logic_error("the hold lists no restore points");
    }
    connector::RestoreResult restore_sample(const connector::RestoreSpec&) override
    {
        throw std::logic_error("the hold restores nothing");
    }
    std::vector<connector::OwnSession>
    own_sessions(std::chrono::system_clock::time_point since) override
    {
        ++fake_.looks;
        fake_.since = since;
        if (fake_.look_throw) {
            fake_.look_throw();
        }
        return fake_.running;
    }
    void end_session(const std::string& id) override
    {
        fake_.ended.push_back(id);
        std::erase_if(fake_.running,
                      [&id](const connector::OwnSession& session) { return session.id == id; });
    }

private:
    HoldFake& fake_;
};

// The body's surroundings: the Harness for everything a run reaches, a
// service context on its config and logger, the three folders in its temp
// folder, a fake Cloud and fake locks.
struct BodyLab {
    Harness h;
    std::shared_ptr<rp::ServiceContext> context = std::make_shared<rp::ServiceContext>();
    rp::WorkerBodyOptions options;
    rp::test::FakeHttpClient cloud;
    int cloud_status = 202;
    int cloud_clients = 0;
    std::vector<milliseconds> waits;
    bool run_lock_taken = false;
    bool run_lock_held = false;
    int run_lock_calls = 0;
    bool flush_lock_taken = false;
    bool flush_lock_held = false;
    // Set: the connector the body makes is the hold's.
    std::optional<HoldFake> hold;

    BodyLab()
    {
        h.fake.pool.mail = {carol_mail(1)};
        context->config = rp::load_config(h.config_path);
        context->config.jobs_file = utf8(jobs_file());
        context->config_path = h.config_path;
        context->logger = h.logger;
        options.runs_root = runs();
        options.outbox_root = box();
        options.state_dir = h.dir.path() / "state";
        options.vault = h.dir.path() / "vault.bin";
        options.pipeline_env = [this] {
            rp::RestoreCommandEnv env = h.env();
            if (hold) {
                env.make_connector = [this](const rp::Config&, const rp::Secrets& secrets,
                                            const connector::ConnectorOptions&)
                    -> std::unique_ptr<connector::IConnector> {
                    ++hold->made;
                    hold->secrets = secrets;
                    return std::make_unique<HoldConnector>(*hold);
                };
            }
            return env;
        };
        options.make_cloud_http = [this](const rp::Config&, std::shared_ptr<spdlog::logger>)
            -> std::unique_ptr<rp::IHttpClient> {
            ++cloud_clients;
            return std::make_unique<rp::test::ForwardingHttpClient>(cloud);
        };
        options.take_run_lock = [this]() -> std::unique_ptr<rp::RunLock> {
            ++run_lock_calls;
            if (run_lock_taken) {
                return nullptr;
            }
            return std::make_unique<Harness::FakeLock>(run_lock_held);
        };
        options.take_flush_lock = [this]() -> std::unique_ptr<rp::RunLock> {
            if (flush_lock_taken) {
                return nullptr;
            }
            return std::make_unique<Harness::FakeLock>(flush_lock_held);
        };
        options.wall_now = [this] { return h.wall_now(); };
        options.wait = [this](milliseconds time) {
            waits.push_back(time);
            return context->stop.requested();
        };
        cloud.on(rp::HttpMethod::post, kResultsUrl,
                 [this](const rp::HttpRequest&) { return rp::test::cloud_answer(cloud_status); });
        cloud.on(rp::HttpMethod::post, kHeartbeatUrl,
                 [](const rp::HttpRequest&) { return rp::test::make_response(204); });
    }

    std::filesystem::path runs() const { return h.dir.path() / "runs"; }
    std::filesystem::path box() const { return h.dir.path() / "box"; }
    std::filesystem::path queued(const std::string& id) const { return box() / "outbox" / id; }
    std::filesystem::path sent(const std::string& id) const { return box() / "sent" / id; }
    std::filesystem::path jobs_file() const { return h.dir.path() / "jobs.json"; }
    std::filesystem::path record_file() const { return h.dir.path() / "state" / "running.json"; }

    rp::ServiceLoopEnv env() { return rp::make_worker_loop_env(context, options); }

    // The loop on the real env until its `waits`-th wait, which is the stop;
    // each wait before it moves the loop's clock by what was asked. What the
    // heartbeat's last_error would be at the end.
    std::optional<std::string> run_loop(int waits_until_stop = 1)
    {
        rp::ServiceLoopEnv loop_env = env();
        std::chrono::steady_clock::duration clock{0};
        int waited = 0;
        loop_env.now = [&clock] { return std::chrono::steady_clock::time_point{} + clock; };
        loop_env.wait = [&](milliseconds time) {
            if (++waited >= waits_until_stop) {
                context->stop.request();
                return true;
            }
            clock += time;
            return false;
        };
        rp::ServiceLoop loop(std::move(loop_env));
        loop.run();
        return loop.last_error();
    }

    void write_jobs(const json& jobs)
    {
        h.dir.write("jobs.json", json{{"format", "restoreproof.jobs.v1"}, {"jobs", jobs}}.dump(2));
    }

    // A record of a run of this lab's client, as the loop's first write has
    // it.
    rp::RunningRecord record(const std::string& id) const
    {
        return rp::new_run_record(id, std::nullopt, *rp::local_profile(context->config),
                                  rp::test::graph_lab::kNow);
    }

    // The same once its run line was out.
    rp::RunningRecord started_record(const std::string& id) const
    {
        rp::RunStarted started;
        started.run_id = id;
        started.started_at = "2026-09-28T12:00:01.000Z";
        started.restore_point_id = kNewestId;
        started.restore_point_time = kNewestTime;
        started.connector_type = std::string{connector::kVeeamM365};
        started.connector_api = "1";
        return rp::with_run_started(record(id), started);
    }

    // running.json through the body's own file calls.
    bool write_record(const rp::RunningRecord& record)
    {
        const rp::ServiceLoopEnv made = env();
        return rp::RecordStore{made.record_file, made.record_files}.write(record);
    }
};

// The lab client's profile (W4.10): the Harness's config values as a
// restoreproof.client-profile.v1 object, what a job of this lab carries.
inline json lab_profile_json()
{
    const json config = rp::test::restore_command_lab::config_values();
    json profile = {{"format", std::string{rp::kClientProfileFormat}}};
    for (const std::string_view key : rp::kClientProfileKeys) {
        profile[std::string{key}] = config.at(key);
    }
    return profile;
}

// W6.2: the lab's jobs opt in to canaries (the key's presence), as the lab's
// manifest is beside the config; a test drops the key for a run without.
inline json job(const std::string& id, int mail = 2, int sp = 1, int od = 0,
                const std::string& connector = "veeam_m365")
{
    return {{"run_id", id},
            {"client_id", nullptr},
            {"client", lab_profile_json()},
            {"connector", json{{"type", connector}}},
            {"sample_mail", mail},
            {"sample_sp", sp},
            {"sample_od", od},
            {"restore_point", "latest"},
            {"screenshots_enabled", false},
            {"canary_cursor", json::array({0, 0, 0})}};
}

inline bool has(const std::string& text, const std::string& part)
{
    return text.find(part) != std::string::npos;
}

inline std::set<std::string> names_in(const std::filesystem::path& folder)
{
    const std::optional<std::vector<std::string>> names = rp::list_folder(folder);
    REQUIRE(names);
    return {names->begin(), names->end()};
}

inline std::string bytes_of(const std::filesystem::path& file)
{
    const std::optional<std::string> text = file_bytes(file);
    REQUIRE(text);
    return *text;
}

inline json result_in(const std::filesystem::path& folder)
{
    return json::parse(bytes_of(folder / "result.json"));
}

// What `rpworker signer verify` says of the folder under the Harness's key.
inline rp::Verification verify(const std::filesystem::path& folder)
{
    const rp::PublicKey key = rp::test::public_key_of(rp::test::signing_key());
    const std::optional<std::vector<std::string>> names = rp::list_folder(folder);
    REQUIRE(names);
    return rp::Signer::verify_folder(rp::folder_reader(folder), *names, key);
}

const std::set<std::string> kTextFiles{"items.csv", "veeam-session.log"};
const std::set<std::string> kQueuedFolder{"items.csv", "manifest.json", "result.json",
                                          "signature.json", "timestamp.tst", "veeam-session.log"};

inline std::string empty_items_csv()
{
    return rp::EvidenceBuilder::items_csv({}).text;
}

} // namespace rp::test::worker_body_lab
