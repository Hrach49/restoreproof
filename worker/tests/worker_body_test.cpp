// W4.8 (docs/decisions.md 2026-10-08, points 1, 5, 7 and 15's wiring): the
// service's body over its real calls (src/worker_body.hpp). The loop's env
// is the real one: the pipeline in process, the record's real file calls,
// the close plan on real folders, the real outbox, uploader and heartbeat.
// Around it are the restore tests' Harness (a temp folder, a fake connector,
// Graph, the downloads and the TSA on fakes), a fake Cloud, fake locks and a
// wait that costs no time. No test waits, starts the service, reads the
// vault or touches %ProgramData%. Failures first.

#include "../src/worker_body.hpp"

#include "../src/file_read.hpp"
#include "../src/folder_ops.hpp"

#include "owner_lab.hpp"
#include "restore_command_lab.hpp"
#include "service_lab.hpp"

#include <rp/base64.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/outbox.hpp>
#include <rp/service_command.hpp>
#include <rp/service_errors.hpp>
#include <rp/service_loop.hpp>
#include <rp/service_recovery.hpp>
#include <rp/sha256.hpp>
#include <rp/signer.hpp>
#include <rp/version.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <random>
#include <thread>

namespace {

using namespace rp::test::restore_command_lab;
using nlohmann::ordered_json;
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
                 [this](const rp::HttpRequest&) { return rp::test::make_response(cloud_status); });
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
        return rp::new_run_record(id, std::nullopt, context->config, rp::test::graph_lab::kNow);
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

json job(const std::string& id, int mail = 2, int sp = 1, int od = 0)
{
    return {{"run_id", id},
            {"client_id", nullptr},
            {"sample_mail", mail},
            {"sample_sp", sp},
            {"sample_od", od},
            {"restore_point", "latest"},
            {"screenshots_enabled", false}};
}

bool has(const std::string& text, const std::string& part)
{
    return text.find(part) != std::string::npos;
}

std::set<std::string> names_in(const std::filesystem::path& folder)
{
    const std::optional<std::vector<std::string>> names = rp::list_folder(folder);
    REQUIRE(names);
    return {names->begin(), names->end()};
}

std::string bytes_of(const std::filesystem::path& file)
{
    const std::optional<std::string> text = file_bytes(file);
    REQUIRE(text);
    return *text;
}

json result_in(const std::filesystem::path& folder)
{
    return json::parse(bytes_of(folder / "result.json"));
}

// What `rpworker signer verify` says of the folder under the Harness's key.
rp::Verification verify(const std::filesystem::path& folder)
{
    const rp::PublicKey key = rp::test::public_key_of(rp::test::signing_key());
    const std::optional<std::vector<std::string>> names = rp::list_folder(folder);
    REQUIRE(names);
    return rp::Signer::verify_folder(rp::folder_reader(folder), *names, key);
}

const std::set<std::string> kTextFiles{"items.csv", "veeam-session.log"};
const std::set<std::string> kQueuedFolder{"items.csv", "manifest.json", "result.json",
                                          "signature.json", "timestamp.tst", "veeam-session.log"};

std::string empty_items_csv()
{
    return rp::EvidenceBuilder::items_csv({}).text;
}

std::wstring unique_mutex_name()
{
    std::random_device random;
    return L"Local\\RestoreProof-worker-body-test-" + std::to_wstring(GetCurrentProcessId()) +
           L"-" + std::to_wstring(random());
}

} // namespace

// --- the run mutex ---------------------------------------------------------------

TEST_CASE("worker body: the service takes an abandoned run mutex again at once",
          "[worker_body][run_lock]")
{
    const std::wstring name = unique_mutex_name();
    // Keeps the mutex alive after the holder's thread ends.
    HANDLE keep = CreateMutexW(nullptr, FALSE, name.c_str());
    REQUIRE(keep != nullptr);
    std::thread crashed([&name] {
        HANDLE handle = CreateMutexW(nullptr, FALSE, name.c_str());
        if (handle != nullptr) {
            WaitForSingleObject(handle, 0);
            CloseHandle(handle); // ends owning it: abandoned
        }
    });
    crashed.join();
    int tries = 0;
    const std::function<std::unique_ptr<rp::RunLock>()> take = [&] {
        ++tries;
        return rp::try_take_named_lock(name);
    };

    SECTION("the function")
    {
        const std::unique_ptr<rp::RunLock> lock = rp::retaking_abandoned(take);

        CHECK(lock != nullptr);
        CHECK(tries == 2);
    }
    SECTION("the loop's env, and the pipeline's")
    {
        BodyLab lab;
        lab.options.take_run_lock = take;

        const std::unique_ptr<rp::RunLock> lock = lab.env().take_run_lock();

        CHECK(lock != nullptr);
        CHECK(tries == 2);
    }
    CloseHandle(keep);
}

TEST_CASE("worker body: a run mutex a command holds is not taken, and asked for once",
          "[worker_body][run_lock]")
{
    BodyLab lab;
    lab.run_lock_taken = true;

    CHECK(lab.env().take_run_lock() == nullptr);
    CHECK(lab.run_lock_calls == 1);
}

TEST_CASE("worker body: a second abandoned answer goes on to the caller",
          "[worker_body][run_lock]")
{
    int tries = 0;
    const std::function<std::unique_ptr<rp::RunLock>()> take =
        [&]() -> std::unique_ptr<rp::RunLock> {
        ++tries;
        throw rp::AbandonedRunLock();
    };

    CHECK_THROWS_AS(rp::retaking_abandoned(take), rp::AbandonedRunLock);
    CHECK(tries == 2);
}

// --- the close of a run folder (point 7), on real files ----------------------------

TEST_CASE("worker body: with no signing key in the vault nothing is closed",
          "[worker_body][close]")
{
    BodyLab lab;
    const bool vault_throws = GENERATE(false, true);
    CAPTURE(vault_throws);
    lab.h.load_secrets = [vault_throws]() -> rp::Secrets {
        if (vault_throws) {
            throw rp::ConfigError("vault", "the vault file can't be read");
        }
        return {"rp-veeam", "Sentinel-Veeam-Password-9c2e", rp::test::graph_lab::pfx_base64(),
                std::string{rp::test::graph_lab::kPfxPassword}, std::nullopt};
    };
    std::filesystem::create_directories(lab.runs() / "killed-1");

    const rp::CloseRunOutcome outcome = lab.env().close_run(lab.record("killed-1"));

    CHECK(outcome.state == rp::CloseRunState::not_closed);
    CHECK(outcome.word == "vault");
    // Nothing was written: no result, no signature, no text file.
    CHECK(names_in(lab.runs() / "killed-1").empty());
    CHECK(lab.h.tsa_clients == 0);
    CHECK_FALSE(std::filesystem::exists(lab.queued("killed-1")));
}

TEST_CASE("worker body: a result that would hold a secret value is not written",
          "[worker_body][close]")
{
    BodyLab lab;
    // The result names the organisation: a vault whose password is that
    // text makes the result hold a secret value.
    lab.h.load_secrets = [] {
        return rp::Secrets{"rp-veeam", kOrgName, rp::test::graph_lab::pfx_base64(),
                           std::string{rp::test::graph_lab::kPfxPassword},
                           std::string{rp::test::kSigningKey1Base64}};
    };

    const rp::CloseRunOutcome outcome = lab.env().close_run(lab.record("killed-1"));

    CHECK(outcome.state == rp::CloseRunState::not_closed);
    CHECK(outcome.word == "holds_secret");
    CHECK(names_in(lab.runs() / "killed-1") == kTextFiles);
    CHECK(has(lab.h.log(), "[killed-1] evidence error: "));
    CHECK(has(lab.h.log(), "the result holds a secret value; no result.json was written"));
    CHECK_FALSE(std::filesystem::exists(lab.queued("killed-1")));
}

TEST_CASE("worker body: a folder that can't be queued stays complete, and the next close only "
          "queues it",
          "[worker_body][close]")
{
    BodyLab lab;
    bool refuse = true;
    lab.options.outbox_files.move_folder = [&refuse](const std::filesystem::path& from,
                                                     const std::filesystem::path& to) {
        return refuse ? 5ul : rp::move_folder(from, to);
    };
    const rp::RunningRecord record = lab.record("killed-1");
    const std::filesystem::path folder = lab.runs() / "killed-1";

    const rp::CloseRunOutcome first = lab.env().close_run(record);

    REQUIRE(first.state == rp::CloseRunState::not_queued);
    CHECK(first.word == "not_moved");
    const std::string result = bytes_of(folder / "result.json");
    const std::string signature = bytes_of(folder / "signature.json");
    CHECK(rp::to_string(verify(folder).word) == "verified");
    CHECK(lab.h.tsa_clients == 1);

    // The close cut short, done again: nothing is signed twice.
    refuse = false;
    const rp::CloseRunOutcome second = lab.env().close_run(record);

    CHECK(second.state == rp::CloseRunState::queued);
    CHECK(second.word.empty());
    CHECK(lab.h.tsa_clients == 1);
    CHECK_FALSE(std::filesystem::exists(folder));
    CHECK(names_in(lab.queued("killed-1")) == kQueuedFolder);
    CHECK(bytes_of(lab.queued("killed-1") / "result.json") == result);
    CHECK(bytes_of(lab.queued("killed-1") / "signature.json") == signature);
    // The manifest of a folder queued afterwards says what the folder shows.
    const json manifest = json::parse(bytes_of(lab.queued("killed-1") / "manifest.json"));
    CHECK(manifest.at("timestamp") == json{{"code", nullptr}, {"state", "timestamped"}});
    CHECK(has(lab.h.log(), "[killed-1] queued " + utf8(lab.queued("killed-1"))));
}

TEST_CASE("worker body: a text file of another account's is replaced with the other, and the "
          "folder closed over their empty forms verifies",
          "[worker_body][close][owner]")
{
    if (!rp::test::elevated()) {
        SKIP("changing a file's owner needs SeRestorePrivilege: run elevated");
    }
    const std::string name = GENERATE("items.csv", "veeam-session.log");
    CAPTURE(name);
    BodyLab lab;
    const std::filesystem::path folder = lab.runs() / "killed-1";
    std::filesystem::create_directories(folder);
    std::ofstream(folder / "items.csv", std::ios::binary) << "index,type\n0,mail\n";
    std::ofstream(folder / "veeam-session.log", std::ios::binary) << "a session's line\n";
    rp::test::give_to(folder / name, L"S-1-5-19");

    const rp::CloseRunOutcome outcome = lab.env().close_run(lab.started_record("killed-1"));

    REQUIRE(outcome.state == rp::CloseRunState::queued);
    CHECK(outcome.untrusted_text_files);
    const std::filesystem::path queued = lab.queued("killed-1");
    CHECK(names_in(queued) == kQueuedFolder);
    CHECK(bytes_of(queued / "items.csv") == empty_items_csv());
    CHECK(bytes_of(queued / "veeam-session.log").empty());
    CHECK(rp::check_trusted_owner(queued / name) == rp::OwnerTrust::trusted);
    CHECK(rp::to_string(verify(queued).word) == "verified");
    CHECK(result_in(queued).at("status").at("error_code") == "interrupted");
}

TEST_CASE("worker body: text files of this account's are kept as they are, and say nothing of "
          "their owner",
          "[worker_body][close][owner]")
{
    BodyLab lab;
    const std::filesystem::path folder = lab.runs() / "killed-1";
    std::filesystem::create_directories(folder);
    std::ofstream(folder / "items.csv", std::ios::binary) << "index,type\n0,mail\n";

    const rp::CloseRunOutcome outcome = lab.env().close_run(lab.started_record("killed-1"));

    REQUIRE(outcome.state == rp::CloseRunState::queued);
    CHECK_FALSE(outcome.untrusted_text_files);
    CHECK(bytes_of(lab.queued("killed-1") / "items.csv") == "index,type\n0,mail\n");
}

TEST_CASE("worker body: a complete folder whose result.json or signature.json is another "
          "account's is not queued, and the loop says so in a SECURITY line",
          "[worker_body][close][owner]")
{
    if (!rp::test::elevated()) {
        SKIP("changing a file's owner needs SeRestorePrivilege: run elevated");
    }
    const std::string name = GENERATE("result.json", "signature.json");
    CAPTURE(name);
    BodyLab lab;
    bool refuse = true;
    lab.options.outbox_files.move_folder = [&refuse](const std::filesystem::path& from,
                                                     const std::filesystem::path& to) {
        return refuse ? 5ul : rp::move_folder(from, to);
    };
    const rp::RunningRecord record = lab.record("killed-1");
    const std::filesystem::path folder = lab.runs() / "killed-1";
    // A folder with its result.json, left under the runs root.
    REQUIRE(lab.env().close_run(record).state == rp::CloseRunState::not_queued);
    refuse = false;
    const std::set<std::string> complete = names_in(folder);
    rp::test::give_to(folder / name, L"S-1-5-19");

    const rp::CloseRunOutcome outcome = lab.env().close_run(record);

    CHECK(outcome.state == rp::CloseRunState::not_closed);
    CHECK(outcome.word == "untrusted");
    CHECK(names_in(folder) == complete);
    CHECK_FALSE(std::filesystem::exists(lab.queued("killed-1")));

    // And through the loop: the line, the record kept, nothing sent.
    REQUIRE(lab.write_record(record));
    const std::optional<std::string> last_error = lab.run_loop();
    CHECK(last_error == rp::service_error::kRunNotClosed);
    CHECK(has(lab.h.log(), "SECURITY: service: run killed-1: result.json or signature.json is "
                           "owned by neither SYSTEM, Administrators nor this account; the folder "
                           "is not queued"));
    CHECK(has(lab.h.log(), "run killed-1: couldn't be closed (untrusted)"));
    CHECK(std::filesystem::exists(lab.record_file()));
    CHECK_FALSE(std::filesystem::exists(lab.queued("killed-1")));
    CHECK_FALSE(std::filesystem::exists(lab.sent("killed-1")));
}

namespace {

struct FolderCase {
    std::string name;
    // Whether the folder is there, and what is in it.
    bool exists;
    std::map<std::string, std::string> files;
    // The record's close_detail `changed`: the text files are replaced.
    bool changed = false;
};

} // namespace

TEST_CASE("worker body: a run folder at every point a kill can leave it is closed, signed and "
          "queued",
          "[worker_body][close]")
{
    const std::string rows = "index,type\n0,mail\n";
    const std::string log = "a session's line\n";
    const std::string temp = "result.json.0123456789abcdef.tmp";
    const FolderCase row = GENERATE_COPY(
        FolderCase{"not there", false, {}},
        FolderCase{"empty", true, {}},
        FolderCase{"the two text files", true, {{"items.csv", rows}, {"veeam-session.log", log}}},
        FolderCase{"one text file and a temp file", true, {{"items.csv", rows}, {temp, "{"}}},
        FolderCase{"signature.json alone",
                   true,
                   {{"items.csv", rows}, {"veeam-session.log", log}, {"signature.json", "{}"}}},
        FolderCase{"signature.json and timestamp.tst",
                   true,
                   {{"items.csv", rows},
                    {"veeam-session.log", log},
                    {"signature.json", "{}"},
                    {"timestamp.tst", "no token"}}},
        FolderCase{"a screenshot and a file of somebody's",
                   true,
                   {{"veeam-session.log", log}, {"screenshot.png", "png"}, {"notes.txt", "mine"}}},
        FolderCase{"a text file the run had found changed",
                   true,
                   {{"items.csv", rows}, {"veeam-session.log", log}},
                   true});
    CAPTURE(row.name);
    BodyLab lab;
    const std::filesystem::path folder = lab.runs() / "killed-1";
    if (row.exists) {
        std::filesystem::create_directories(folder);
        for (const auto& [name, content] : row.files) {
            std::ofstream(folder / name, std::ios::binary) << content;
        }
    }
    rp::RunningRecord record = lab.started_record("killed-1");
    if (row.changed) {
        record = rp::with_close(record, rp::CloseAs::internal, "changed");
    }

    const rp::CloseRunOutcome outcome = lab.env().close_run(record);

    REQUIRE(outcome.state == rp::CloseRunState::queued);
    CHECK(outcome.word.empty());
    CHECK_FALSE(std::filesystem::exists(folder));
    const std::filesystem::path queued = lab.queued("killed-1");
    // What a signing that didn't finish left is gone; the new signature and
    // token are this close's.
    std::set<std::string> expected = kQueuedFolder;
    if (row.files.contains("notes.txt")) {
        expected.insert("notes.txt");
    }
    CHECK(names_in(queued) == expected);
    const rp::Verification verified = verify(queued);
    CHECK(rp::to_string(verified.word) == "verified");
    CHECK(verified.timestamp == rp::TimestampState::unchecked);
    // A text file that was there is listed as it is; one that wasn't, and
    // both after `changed`, in its empty form.
    const bool keeps = !row.changed;
    CHECK(bytes_of(queued / "items.csv") ==
          (keeps && row.files.contains("items.csv") ? rows : empty_items_csv()));
    CHECK(bytes_of(queued / "veeam-session.log") ==
          (keeps && row.files.contains("veeam-session.log") ? log : ""));
    // The result: what the record knows, and null for the rest.
    const json result = result_in(queued);
    CHECK(result.at("run_id") == "killed-1");
    CHECK(result.at("started_at") == "2026-09-28T12:00:01.000Z");
    CHECK(result.at("ended_at").is_null());
    CHECK(result.at("restore_point").at("id") == kNewestId);
    CHECK(result.at("client").at("veeam_org_name") == kOrgName);
    CHECK(result.at("check").is_null());
    const json& status = result.at("status");
    CHECK(status.at("status") == "error");
    CHECK(status.at("error_code") == (row.changed ? "internal" : "interrupted"));
    CHECK(status.at("restore_sent") == false);
    CHECK(status.at("message") ==
          (row.changed ? "the run ended without a result the Worker could write; this result was "
                         "written afterwards"
                       : "the run was interrupted before its result was written; no restore "
                         "request had been sent"));
    // The tail's own lines are the log's, under the run's ID.
    CHECK(has(lab.h.log(), "[info] [killed-1] signed "));
    CHECK(has(lab.h.log(), "[info] [killed-1] timestamped 2026-09-28T12:00:00Z"));
    CHECK(has(lab.h.log(), "[info] [killed-1] queued " + utf8(queued)));
}

TEST_CASE("worker body: a CA file that can't be used leaves the closed folder signed and not "
          "timestamped",
          "[worker_body][close]")
{
    BodyLab lab;
    lab.context->config.tsa_ca_file = utf8(lab.h.dir.path() / "no-such-ca.pem");

    const rp::CloseRunOutcome outcome = lab.env().close_run(lab.record("killed-1"));

    REQUIRE(outcome.state == rp::CloseRunState::queued);
    CHECK(lab.h.tsa_clients == 0);
    CHECK_FALSE(std::filesystem::exists(lab.queued("killed-1") / "timestamp.tst"));
    CHECK(rp::to_string(verify(lab.queued("killed-1")).word) == "verified");
    CHECK(has(lab.h.log(), "[warning] [killed-1] timestamp warning: the TSA's CA file can't be "
                           "used; not timestamped"));
}

// --- the record's files ------------------------------------------------------------

TEST_CASE("worker body: the record's file calls make the state folder, replace, move aside and "
          "remove",
          "[worker_body][record]")
{
    BodyLab lab;
    const rp::ServiceLoopEnv env = lab.env();
    const rp::RecordStore store{env.record_file, env.record_files};
    CHECK(env.record_file == lab.record_file());
    CHECK_FALSE(std::filesystem::exists(lab.record_file().parent_path()));
    CHECK(store.read().state == rp::RecordState::none);

    // Written, the folder made; written again over itself.
    REQUIRE(store.write(lab.record("run-a")));
    REQUIRE(store.write(lab.started_record("run-a")));
    const rp::RecordRead read = store.read();
    REQUIRE(read.state == rp::RecordState::record);
    CHECK(*read.record == lab.started_record("run-a"));
    CHECK(names_in(lab.record_file().parent_path()) == std::set<std::string>{"running.json"});

    // Something that is no record is moved aside, over an older one.
    lab.h.dir.write("state/running.json.unread", "older");
    lab.h.dir.write("state/running.json", "not a record");
    CHECK(store.read().state == rp::RecordState::not_record);
    CHECK(store.move_aside());
    CHECK(bytes_of(store.unread_file()) == "not a record");
    CHECK(store.read().state == rp::RecordState::none);
    // With nothing there, nothing is moved; a remove of nothing is done.
    CHECK_FALSE(store.move_aside());
    CHECK(store.erase());

    REQUIRE(store.write(lab.record("run-b")));
    CHECK(store.erase());
    CHECK_FALSE(std::filesystem::exists(lab.record_file()));
}

// --- the small calls ---------------------------------------------------------------

TEST_CASE("worker body: what the loop asks of the folders", "[worker_body]")
{
    BodyLab lab;
    const rp::ServiceLoopEnv env = lab.env();

    CHECK(env.jobs_file == lab.jobs_file());
    CHECK(env.runs_root == lab.runs());
    CHECK(env.outbox_root == lab.box());
    CHECK(env.logger == lab.h.logger);
    CHECK(env.wall_now() == rp::test::graph_lab::kNow);
    // No file is no jobs.
    CHECK(env.read_jobs(lab.jobs_file()).state == rp::JobsState::no_file);

    CHECK(env.outbox_depth() == 0);
    CHECK(env.outbox_holds("run-a") == rp::OutboxHolds::none);
    CHECK_FALSE(env.run_folder_exists("run-a"));
    CHECK_FALSE(env.run_folder_exists("\xff"));
    std::filesystem::create_directories(lab.runs() / "run-a");
    std::filesystem::create_directories(lab.queued("run-b"));
    std::filesystem::create_directories(lab.queued("run-c"));
    std::filesystem::create_directories(lab.sent("run-d"));
    lab.h.dir.write("box/outbox/a-file", "no run");
    CHECK(env.run_folder_exists("run-a"));
    CHECK(env.outbox_holds("run-b") == rp::OutboxHolds::queued);
    CHECK(env.outbox_holds("run-d") == rp::OutboxHolds::sent);
    // The folders under outbox\, the ones that can't be sent included.
    CHECK(env.outbox_depth() == 2);

    // The wait is the options': it costs no time and answers the stop.
    CHECK_FALSE(env.wait(milliseconds{300000}));
    CHECK_FALSE(env.stop_requested());
    lab.context->stop.request();
    CHECK(env.wait(milliseconds{5}));
    CHECK(env.stop_requested());
    CHECK(lab.waits == std::vector<milliseconds>{milliseconds{300000}, milliseconds{5}});
}

TEST_CASE("worker body: without the config key there is no job source", "[worker_body]")
{
    BodyLab lab;
    lab.context->config.jobs_file.reset();

    CHECK_FALSE(lab.env().jobs_file);
}

TEST_CASE("worker body: a flush is skipped while another holds its mutex, and the Cloud's "
          "client is made once",
          "[worker_body][flush]")
{
    BodyLab lab;
    rp::ServiceLoopEnv env = lab.env();
    lab.flush_lock_taken = true;

    CHECK_FALSE(env.flush({}));
    CHECK(lab.cloud_clients == 0);

    lab.flush_lock_taken = false;
    const std::optional<rp::FlushReport> report = env.flush({});
    REQUIRE(report);
    CHECK(report->queued == 0);
    CHECK_FALSE(lab.flush_lock_held);

    // The heartbeat goes through the same client: the body the Cloud gets.
    rp::LoopHeartbeat beat;
    beat.last_error = "run_not_closed";
    beat.last_error_at = rp::test::graph_lab::kNow;
    beat.outbox_depth = 3;
    beat.uptime_s = 77;
    CHECK(env.heartbeat(beat).empty());
    CHECK(lab.cloud_clients == 1);
    const std::vector<rp::HttpRequest> requests = lab.cloud.requests();
    REQUIRE(requests.size() == 1);
    CHECK(requests[0].url == kHeartbeatUrl);
    CHECK(requests[0].body == "{\"last_error\":\"run_not_closed\",\"last_error_at\":"
                              "\"2026-09-28T12:00:00.000Z\",\"outbox_depth\":3,\"uptime_s\":77,"
                              "\"version\":\"" +
                                  std::string{rp::version()} + "\"}");

    // A failed one answers its word.
    lab.cloud.on(rp::HttpMethod::post, kHeartbeatUrl, {rp::test::make_response(503)});
    CHECK(env.heartbeat(beat) == "http_503");
}

TEST_CASE("worker body: a stop that comes during an upload ends the flush before the next run: "
          "one POST, and the second run still queued",
          "[worker_body][flush]")
{
    BodyLab lab;
    // Two runs in the outbox, each a folder closed and queued.
    REQUIRE(lab.env().close_run(lab.record("killed-1")).state == rp::CloseRunState::queued);
    // The second a second later, so that the flush's order is theirs.
    lab.h.wall_now = [earlier = lab.h.wall_now] { return earlier() + std::chrono::seconds{1}; };
    REQUIRE(lab.env().close_run(lab.record("killed-2")).state == rp::CloseRunState::queued);
    lab.context->config.jobs_file.reset();
    // The Cloud takes the first run; the stop is asked for while it answers.
    lab.cloud.on(rp::HttpMethod::post, kResultsUrl, [&lab](const rp::HttpRequest&) {
        lab.context->stop.request();
        return rp::test::make_response(202);
    });

    lab.run_loop(5);

    std::size_t posts = 0;
    for (const rp::HttpRequest& request : lab.cloud.requests()) {
        posts += request.url == kResultsUrl ? 1u : 0u;
    }
    CHECK(posts == 1);
    // The older one went; the other was never started and is as it was.
    CHECK(std::filesystem::exists(lab.sent("killed-1")));
    CHECK_FALSE(std::filesystem::exists(lab.queued("killed-1")));
    CHECK(names_in(lab.queued("killed-2")) == kQueuedFolder);
    CHECK_FALSE(std::filesystem::exists(lab.sent("killed-2")));
    const json manifest = json::parse(bytes_of(lab.queued("killed-2") / "manifest.json"));
    CHECK(manifest.at("attempts") == 0);
    CHECK(rp::to_string(verify(lab.queued("killed-2")).word) == "verified");
}

TEST_CASE("worker body: a Cloud client that can't be made is the step's failure",
          "[worker_body][flush]")
{
    BodyLab lab;
    lab.options.make_cloud_http = [](const rp::Config&, std::shared_ptr<spdlog::logger>) {
        return std::unique_ptr<rp::IHttpClient>{};
    };
    rp::ServiceLoopEnv env = lab.env();

    CHECK_THROWS(env.heartbeat({}));
    CHECK_THROWS(env.flush({}));
}

// --- the hold's connector (point 9) --------------------------------------------------

TEST_CASE("worker body: the hold has one connector, dropped after a look that fails and when "
          "the hold is over",
          "[worker_body][hold]")
{
    BodyLab lab;
    lab.hold.emplace();
    lab.hold->running = {{kSessionA, rp::test::graph_lab::kNow}};
    rp::ServiceLoopEnv env = lab.env();
    const auto since = rp::test::graph_lab::kNow - std::chrono::minutes{5};

    const rp::SessionsLook first = env.own_sessions(since);
    CHECK(first.account == "rp-veeam");
    REQUIRE(first.running.size() == 1);
    CHECK(first.running[0].id == kSessionA);
    CHECK(lab.hold->since == since);
    // The connector's copy of the secrets is without the signing key.
    REQUIRE(lab.hold->secrets);
    CHECK_FALSE(lab.hold->secrets->signing_key_base64);
    CHECK(lab.hold->secrets->veeam_password == "Sentinel-Veeam-Password-9c2e");

    env.end_session(kSessionA);
    CHECK(lab.hold->ended == std::vector<std::string>{kSessionA});
    CHECK(env.own_sessions(since).running.empty());
    CHECK(lab.hold->made == 1);

    // A look that fails: the connector's own error goes on, and the next
    // look makes a new one.
    lab.hold->look_throw = [] { throw connector::TransientError("veeam_m365: not now"); };
    CHECK_THROWS_AS(env.own_sessions(since), connector::TransientError);
    lab.hold->look_throw = nullptr;
    env.own_sessions(since);
    CHECK(lab.hold->made == 2);

    env.release_hold();
    env.own_sessions(since);
    CHECK(lab.hold->made == 3);

    // No vault: the look fails before any connector is made.
    env.release_hold();
    lab.h.load_secrets = []() -> rp::Secrets {
        throw rp::ConfigError("vault", "vault file not found");
    };
    CHECK_THROWS_AS(env.own_sessions(since), rp::ConfigError);
    CHECK(lab.hold->made == 3);
}

// --- the loop on the real env --------------------------------------------------------

TEST_CASE("worker body: a record left by a killed run is closed as error interrupted, signed, "
          "queued and sent",
          "[worker_body][loop]")
{
    BodyLab lab;
    // What a kill during the restore leaves: the record and an empty folder.
    REQUIRE(lab.write_record(lab.started_record("killed-1")));
    std::filesystem::create_directories(lab.runs() / "killed-1");

    const std::optional<std::string> last_error = lab.run_loop();

    CHECK_FALSE(last_error);
    const std::string log = lab.h.log();
    CHECK(has(log, "[warning] interrupted run killed-1 found: taken 2026-09-28T12:00:00.000Z, "
                   "restore requested no"));
    CHECK(has(log, "[info] run killed-1: queued"));
    CHECK(has(log, "[info] sent killed-1"));
    // Nothing was asked of Veeam or Graph for it.
    CHECK(lab.h.make_connector_calls == 0);
    CHECK(lab.h.graph_clients == 0);
    // In sent\, as the run signed it, and the record gone.
    CHECK_FALSE(std::filesystem::exists(lab.runs() / "killed-1"));
    CHECK_FALSE(std::filesystem::exists(lab.queued("killed-1")));
    CHECK_FALSE(std::filesystem::exists(lab.record_file()));
    const std::filesystem::path sent = lab.sent("killed-1");
    CHECK(names_in(sent) == kQueuedFolder);
    const rp::Verification verified = verify(sent);
    CHECK(rp::to_string(verified.word) == "verified");
    CHECK(verified.notes == std::vector<std::string>{"manifest.json"});
    const json status = result_in(sent).at("status");
    CHECK(status.at("status") == "error");
    CHECK(status.at("error_code") == "interrupted");
    CHECK(status.at("restore_sent") == false);
    // What the Cloud got: the first heartbeat, then the run's parts.
    const std::vector<rp::HttpRequest> requests = lab.cloud.requests();
    REQUIRE(requests.size() == 2);
    CHECK(requests[0].url == kResultsUrl);
    REQUIRE(requests[0].parts.size() == 5);
    CHECK(requests[0].parts[0].name == "result");
    CHECK(requests[0].parts[0].content == bytes_of(sent / "result.json"));
    CHECK(requests[1].url == kHeartbeatUrl);
}

TEST_CASE("worker body: after a restore request the hold looks, ends the run's own sessions and "
          "cleans the targets before the record goes",
          "[worker_body][loop][hold]")
{
    BodyLab lab;
    lab.hold.emplace();
    const bool requested = GENERATE(false, true);
    CAPTURE(requested);
    rp::RunningRecord record = rp::with_session(lab.started_record("killed-1"), kSessionA);
    if (requested) {
        record = rp::with_restore_request(record, rp::test::graph_lab::kNow);
    } else {
        // No request went out: the run's own session is ended at once, the
        // other is not the run's.
        lab.hold->running = {{kSessionA, rp::test::graph_lab::kNow},
                             {kSessionB, rp::test::graph_lab::kNow}};
    }
    REQUIRE(lab.write_record(record));

    const std::optional<std::string> last_error = lab.run_loop();

    CHECK_FALSE(last_error);
    const std::string log = lab.h.log();
    CHECK(lab.hold->made == 1);
    CHECK(lab.hold->since == rp::test::graph_lab::kNow);
    CHECK_FALSE(std::filesystem::exists(lab.record_file()));
    CHECK(result_in(lab.sent("killed-1")).at("status").at("restore_sent") == requested);
    // The looks were made under the run mutex, let go again.
    CHECK(lab.run_lock_calls >= 1);
    CHECK_FALSE(lab.run_lock_held);
    if (requested) {
        CHECK(lab.hold->ended.empty());
        // The clean the run never made, its lines the log's.
        CHECK(has(log, "[info] recovery clean for killed-1:"));
        CHECK(has(log, "[info] [killed-1] cleanup before ok: deleted 0 mail, 0 sharepoint, 0 "
                       "onedrive"));
        CHECK(lab.h.graph_clients == 1);
    } else {
        CHECK(lab.hold->ended == std::vector<std::string>{kSessionA});
        CHECK_FALSE(has(log, "recovery clean"));
        CHECK(lab.h.graph_clients == 0);
    }
}

TEST_CASE("worker body: a look that fails keeps the record, and each look makes a new connector",
          "[worker_body][loop][hold]")
{
    BodyLab lab;
    lab.hold.emplace();
    lab.hold->look_throw = [] { throw connector::AuthError("veeam_m365: sign-in failed"); };
    REQUIRE(lab.write_record(
        rp::with_restore_request(lab.started_record("killed-1"), rp::test::graph_lab::kNow)));

    // The start, the first poll, and one look 30 s later.
    const std::optional<std::string> last_error = lab.run_loop(2);

    CHECK(last_error == "veeam_look_failed");
    CHECK(has(lab.h.log(), "[warning] the look at Veeam's sessions failed: auth"));
    CHECK(lab.hold->looks == 3);
    CHECK(lab.hold->made == 3);
    // Closed and sent all the same; the record stays until the hold is over.
    CHECK(std::filesystem::exists(lab.sent("killed-1") / "result.json"));
    const rp::ServiceLoopEnv env = lab.env();
    const rp::RecordRead read = rp::RecordStore{env.record_file, env.record_files}.read();
    REQUIRE(read.state == rp::RecordState::record);
    CHECK(read.record->run_id == "killed-1");
    CHECK(lab.h.graph_clients == 0);
}

TEST_CASE("worker body: a job that is no job is reported as error job_invalid, signed and "
          "queued, with nothing asked of Veeam or Graph",
          "[worker_body][loop]")
{
    BodyLab lab;
    lab.cloud_status = 503;
    lab.write_jobs(json::array({job("bad-1", 0, 0, 0)}));

    // Two polls: the second skips the job.
    const std::optional<std::string> last_error = lab.run_loop(2);

    CHECK(last_error == "upload_http_503");
    const std::string log = lab.h.log();
    CHECK(has(log, "[warning] job bad-1: not a valid job (sample_mail)"));
    CHECK(has(log, "[info] run bad-1: queued"));
    CHECK(has(log, "[info] kept bad-1: upload_http_503; attempt 1, next at "));
    CHECK(has(log, "[info] skipped bad-1: already queued"));
    CHECK(lab.h.make_connector_calls == 0);
    CHECK(lab.h.graph_clients == 0);
    CHECK(lab.h.load_secrets_calls == 1);
    CHECK_FALSE(std::filesystem::exists(lab.record_file()));
    const std::filesystem::path queued = lab.queued("bad-1");
    CHECK(names_in(queued) == kQueuedFolder);
    CHECK(rp::to_string(verify(queued).word) == "verified");
    const json result = result_in(queued);
    CHECK(result.at("started_at").is_null());
    CHECK(result.at("restore_point") ==
          json{{"backup_time", nullptr}, {"backup_time_raw", ""}, {"id", ""}});
    CHECK(result.at("connector") == json{{"api", ""}, {"type", "veeam_m365"}});
    const json& status = result.at("status");
    CHECK(status.at("status") == "error");
    CHECK(status.at("error_code") == "job_invalid");
    CHECK(status.at("restore_sent") == false);
    CHECK(status.at("message") == "the job isn't a valid job (sample_mail); nothing was done");
    CHECK(bytes_of(queued / "items.csv") == empty_items_csv());
    CHECK(bytes_of(queued / "veeam-session.log").empty());
}

TEST_CASE("worker body: one job from the stub file to the outbox and the Cloud, the record "
          "written before the restore request and gone at the end",
          "[worker_body][loop]")
{
    BodyLab lab;
    lab.write_jobs(json::array({job("job-1")}));
    // The fake connector tells its caller as the real one does: a session
    // opened, then the request about to go. What running.json held then.
    std::optional<bool> let_go;
    std::optional<std::string> record_before_request;
    std::optional<std::string> record_at_request;
    // What the service's wait was asked for by the pipeline's sleep and by
    // the download client's, each called once from inside the run.
    std::vector<milliseconds> pipeline_waits;
    std::vector<milliseconds> download_waits;
    lab.h.fake.at_restore = [&] {
        const connector::ConnectorOptions& told = *lab.h.connector_options;
        told.on_session_opened(kSessionA);
        record_before_request = file_bytes(lab.record_file());
        let_go = told.before_restore_request();
        record_at_request = file_bytes(lab.record_file());
        std::size_t before = lab.waits.size();
        told.sleep(milliseconds{1234});
        pipeline_waits.assign(lab.waits.begin() + static_cast<std::ptrdiff_t>(before),
                              lab.waits.end());
        before = lab.waits.size();
        if (lab.h.download_sleep) {
            lab.h.download_sleep(milliseconds{5678});
        }
        download_waits.assign(lab.waits.begin() + static_cast<std::ptrdiff_t>(before),
                              lab.waits.end());
    };

    const std::optional<std::string> last_error = lab.run_loop();

    CHECK_FALSE(last_error);
    // The pipeline's sleep and the download client's are the service's wait,
    // which a stop ends: not the Harness's, and not a real sleep.
    CHECK(pipeline_waits == std::vector<milliseconds>{milliseconds{1234}});
    CHECK(download_waits == std::vector<milliseconds>{milliseconds{5678}});
    CHECK(std::ranges::find(lab.h.slept, milliseconds{1234}) == lab.h.slept.end());
    // The record: on disk before the request was let go.
    REQUIRE(let_go);
    CHECK(*let_go);
    REQUIRE(record_before_request);
    REQUIRE(record_at_request);
    const std::optional<rp::RunningRecord> before = rp::parse_record(*record_before_request);
    const std::optional<rp::RunningRecord> at = rp::parse_record(*record_at_request);
    REQUIRE(before);
    REQUIRE(at);
    CHECK(before->run_id == "job-1");
    CHECK(before->kind == rp::RecordKind::run);
    CHECK(before->taken_at == "2026-09-28T12:00:00.000Z");
    REQUIRE(before->restore_point);
    CHECK(before->restore_point->id == kNewestId);
    CHECK(before->restore_point->backup_time_raw == kNewestTime);
    REQUIRE(before->connector);
    CHECK(before->started_at.has_value());
    CHECK(before->sessions == std::vector<std::string>{kSessionA});
    CHECK_FALSE(before->restore_requested);
    CHECK(at->restore_requested);
    CHECK(at->restore_requested_at == "2026-09-28T12:00:00.000Z");
    CHECK_FALSE(at->close_as);
    // The run: test's pipeline with the job's sizes, the service's stop
    // check and sleep, its run mutex and its vault.
    REQUIRE(lab.h.fake.spec);
    CHECK(lab.h.fake.spec->mail.size() == 2);
    CHECK(lab.h.fake.spec->sharepoint.size() == 1);
    CHECK(lab.h.fake.spec->onedrive.empty());
    CHECK(lab.h.vault_read == lab.h.dir.path() / "vault.bin");
    CHECK(lab.h.connector_options->stop_requested);
    CHECK(lab.h.download_sleep);
    CHECK(lab.h.lock_calls == 0);
    CHECK(lab.run_lock_calls == 1);
    CHECK_FALSE(lab.run_lock_held);
    // The log: the loop's lines and the run's own, under its ID.
    const std::string log = lab.h.log();
    CHECK(has(log, "[info] scheduler started: poll 300 s, heartbeat 900 s, jobs " +
                       utf8(lab.jobs_file()) + ", runs " + utf8(lab.runs()) + ", outbox " +
                       utf8(lab.box())));
    CHECK(has(log, "[info] run job-1: starting (mail 2, sharepoint 1, onedrive 0, point latest)"));
    CHECK(has(log, "[info] [job-1] run job-1  seed " + seed_of("job-1")));
    CHECK(has(log, "[info] [job-1] status pass: 3 of 3 item(s) verified: manifest 2, fields 1, "
                   "metadata 0"));
    CHECK(has(log, "[info] [job-1] cleanup after ok: deleted 2 mail, 1 sharepoint, 0 onedrive"));
    CHECK(has(log, "[info] [job-1] queued " + utf8(lab.queued("job-1"))));
    CHECK(has(log, "[info] run job-1: ended pass; queued"));
    CHECK(has(log, "[info] sent job-1"));
    // The connector's own line went to the service's log too.
    CHECK(has(log, "fake connector: SENTINEL-LOG-LINE"));
    CHECK(log.find("run job-1: starting") < log.find("[job-1] run job-1"));
    CHECK(log.find("run job-1: ended pass; queued") < log.find("sent job-1"));
    // The folder: sent, verified, a pass; nothing left behind.
    const std::filesystem::path sent = lab.sent("job-1");
    CHECK(names_in(sent) == kQueuedFolder);
    CHECK(rp::to_string(verify(sent).word) == "verified");
    const json result = result_in(sent);
    CHECK(result.at("status").at("status") == "pass");
    CHECK(result.at("client").at("client_id").is_null());
    CHECK_FALSE(std::filesystem::exists(lab.runs() / "job-1"));
    CHECK_FALSE(std::filesystem::exists(lab.queued("job-1")));
    CHECK_FALSE(std::filesystem::exists(lab.record_file()));
    // The Cloud: the first heartbeat (nothing queued, no error), then the
    // run's five parts.
    const std::vector<rp::HttpRequest> requests = lab.cloud.requests();
    REQUIRE(requests.size() == 2);
    CHECK(requests[0].url == kHeartbeatUrl);
    const json beat = json::parse(requests[0].body);
    CHECK(beat.at("outbox_depth") == 0);
    CHECK(beat.at("last_error").is_null());
    CHECK(requests[1].url == kResultsUrl);
    REQUIRE(requests[1].parts.size() == 5);
    CHECK(requests[1].parts[0].content == bytes_of(sent / "result.json"));
    CHECK(lab.cloud_clients == 1);
}

TEST_CASE("worker body: after a stop the restore request is not let go and the record doesn't "
          "say one was",
          "[worker_body][loop]")
{
    BodyLab lab;
    lab.write_jobs(json::array({job("job-1")}));
    std::optional<bool> let_go;
    std::optional<std::string> record_at_request;
    lab.h.fake.at_restore = [&] {
        lab.context->stop.request();
        let_go = lab.h.connector_options->before_restore_request();
        record_at_request = file_bytes(lab.record_file());
    };

    lab.run_loop();

    REQUIRE(let_go);
    CHECK_FALSE(*let_go);
    REQUIRE(record_at_request);
    const std::optional<rp::RunningRecord> at = rp::parse_record(*record_at_request);
    REQUIRE(at);
    CHECK_FALSE(at->restore_requested);
    CHECK_FALSE(at->restore_requested_at);
    // The stop is the pipeline's too: its check and its sleep are the
    // service's.
    CHECK(lab.h.connector_options->stop_requested());
}

TEST_CASE("worker body: a run that ends before its run line leaves no folder and no record",
          "[worker_body][loop]")
{
    BodyLab lab;
    lab.write_jobs(json::array({job("job-1")}));
    lab.run_lock_taken = true;

    const std::optional<std::string> last_error = lab.run_loop();

    CHECK(last_error == "job_not_started");
    const std::string log = lab.h.log();
    CHECK(has(log, "[warning] [job-1] restore error: another RestoreProof run is using the "
                   "restore targets; nothing was done"));
    CHECK(has(log, "[warning] run job-1: ended before its run line; nothing was done"));
    CHECK_FALSE(std::filesystem::exists(lab.runs() / "job-1"));
    CHECK_FALSE(std::filesystem::exists(lab.record_file()));
    CHECK(lab.h.fake.points_calls == 0);
}

TEST_CASE("worker body: a pipeline env that can't be made is a run that did nothing",
          "[worker_body]")
{
    BodyLab lab;
    lab.options.pipeline_env = []() -> rp::RestoreCommandEnv { throw std::runtime_error("no"); };
    const rp::ServiceLoopEnv env = lab.env();
    rp::Job one;
    one.run_id = "job-1";
    one.sample_mail = 1;
    one.restore_point = "latest";

    const rp::JobRun run = env.run_job(one, {});

    CHECK(run.exit_code == 1);
    CHECK_FALSE(run.run_line);
    CHECK(run.folder == rp::JobFolder::none);
    CHECK_FALSE(run.status);
}

// --- the wiring: `service run` -------------------------------------------------------

TEST_CASE("service run: the real body on the fake host says the scheduler started and stops "
          "cleanly",
          "[worker_body][service_command][run]")
{
    using namespace rp::test::service_lab;
    const rp::test::TempDir tmp;
    const std::filesystem::path config = tmp.write("config.json", config_json());
    const std::filesystem::path log_dir = tmp.path() / "logs";
    FakeHost fake;
    rp::test::FakeHttpClient cloud;
    bool lock_held = false;
    rp::WorkerBodyOptions options;
    options.runs_root = tmp.path() / "runs";
    options.outbox_root = tmp.path() / "box";
    options.state_dir = tmp.path() / "state";
    options.vault = tmp.path() / "vault.bin";
    options.make_cloud_http = [&cloud](const rp::Config&, std::shared_ptr<spdlog::logger>)
        -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(cloud);
    };
    options.take_run_lock = [&lock_held]() -> std::unique_ptr<rp::RunLock> {
        return std::make_unique<Harness::FakeLock>(lock_held);
    };
    options.take_flush_lock = options.take_run_lock;
    // The body is let go only once the stop was given: it starts nothing.
    rp::StopSignal gate;
    const rp::ServiceBody real = rp::make_worker_body(options);
    rp::ServiceCommandEnv env;
    env.host = fake.host();
    env.default_log_dir = [&] { return log_dir; };
    env.default_config_path = [&] { return config; };
    env.body = [&gate, &real](const std::shared_ptr<rp::ServiceContext>& context) {
        gate.wait();
        real(context);
    };
    std::ostringstream out;
    std::ostringstream err;
    int code = -1;

    std::thread runner{
        [&] { code = rp::run_service_command(Args{"run"}, out, err, env); }};
    const bool running = fake.wait_for_state(rp::ServiceState::running);
    if (fake.has_handler()) {
        fake.control(rp::ServiceControl::stop);
    }
    gate.request();
    runner.join();
    fake.forget();

    REQUIRE(running);
    CHECK(code == 0);
    CHECK(out.str().empty());
    CHECK(err.str().empty());
    CHECK(fake.exits().empty());
    std::ifstream stream(log_dir / rp::kLogFileName, std::ios::binary);
    std::ostringstream text;
    text << stream.rdbuf();
    const std::string log = text.str();
    CHECK(has(log, " info scheduler started: poll 300 s, heartbeat 900 s, jobs none, runs " +
                       utf8(tmp.path() / "runs") + ", outbox " + utf8(tmp.path() / "box") +
                       "\r\n"));
    CHECK(has(log, " info service stopped after "));
    CHECK_FALSE(has(log, " error "));
    // Nothing was begun: no folder made, nothing asked of the Cloud.
    CHECK(cloud.requests().empty());
    CHECK_FALSE(std::filesystem::exists(tmp.path() / "state"));
    CHECK_FALSE(std::filesystem::exists(tmp.path() / "box"));
}

// --- the shared vector of a closed folder (point 15) ---------------------------------

namespace {

const char* const kClosedVector = "testdata/signing-v1/closed-folder.json";

// One folder closed by the service as `error interrupted`, as texts: the
// client is result-v1's made-up one, the key RFC 8032's test key 1. The stop
// is asked for first, so no TSA is asked and the folder has no token.
ordered_json closed_vector()
{
    BodyLab lab;
    rp::Config& config = lab.context->config;
    config.veeam_org_name = "contoso.onmicrosoft.com";
    config.graph_tenant_id = "11111111-2222-3333-4444-555555555555";
    config.test_mailbox = "restoretest@contoso.onmicrosoft.com";
    config.test_site_id = "contoso.sharepoint.com,aaaaaaaa-0000-0000-0000-000000000001,"
                          "aaaaaaaa-0000-0000-0000-000000000002";
    config.test_library_id = "b!library";
    config.test_onedrive_drive_id = "b!onedrive";
    config.test_onedrive_folder_id = "01FOLDER";
    rp::RunStarted started;
    started.run_id = "closed-run-1";
    started.started_at = "2026-10-08T09:00:01.000Z";
    started.restore_point_id = "restore-point-1";
    started.restore_point_time = "2026-10-07T22:00:45.6603083Z";
    started.connector_type = std::string{connector::kVeeamM365};
    started.connector_api = "v8";
    const rp::RunningRecord record = rp::with_restore_request(
        rp::with_run_started(lab.record("closed-run-1"), started), rp::test::graph_lab::kNow);
    lab.context->stop.request();

    const rp::CloseRunOutcome outcome = lab.env().close_run(record);

    REQUIRE(outcome.state == rp::CloseRunState::queued);
    const std::filesystem::path folder = lab.queued("closed-run-1");
    REQUIRE(names_in(folder) == std::set<std::string>{"items.csv", "manifest.json", "result.json",
                                                      "signature.json", "veeam-session.log"});
    const rp::Verification verified = verify(folder);
    REQUIRE(rp::to_string(verified.word) == "verified");
    return {{"description",
             "One run folder the Worker's service closed afterwards (W4.8, docs/decisions.md "
             "2026-10-08, point 7), as texts, in bundle.json's shape: `files` maps each file's "
             "name to its content, a file's bytes the UTF-8 of that string exactly. The run's "
             "process ended after a restore request and before its result was written, so the "
             "result says `error interrupted` with `restore_sent` true, every step null and the "
             "two text files in their empty forms; it is signed with the key `key` of keys.json "
             "and has no timestamp.tst. With that key's `public_key_pem` both verifiers answer "
             "`verified <bundle_sha256> key <key_id> timestamp none`. Written by the Worker's "
             "hidden test `rptests \"[.write_shared_closed]\"`; the result names the Worker's "
             "version of that day, so the file is not held to the code byte for byte: a Worker "
             "test and a Cloud test verify it as it is."},
            {"key", rp::test::kSigningKey1Name},
            {"bundle_sha256", verified.bundle_sha256},
            {"key_id", verified.key_id},
            {"files",
             {{"items.csv", bytes_of(folder / "items.csv")},
              {"result.json", bytes_of(folder / "result.json")},
              {"signature.json", bytes_of(folder / "signature.json")},
              {"veeam-session.log", bytes_of(folder / "veeam-session.log")}}}};
}

} // namespace

TEST_CASE("worker body: writes the shared vector of a closed folder", "[.write_shared_closed]")
{
    std::ofstream file(std::filesystem::path{RP_SHARED_DIR} / kClosedVector,
                       std::ios::binary | std::ios::trunc);
    file << closed_vector().dump(2) << '\n';
    file.close();
    REQUIRE(file);
}

TEST_CASE("worker body: a folder closed after a stop has no token, and is what the shared "
          "vector holds",
          "[worker_body][close][signer]")
{
    const ordered_json made = closed_vector();
    const std::optional<std::string> text =
        file_bytes(std::filesystem::path{RP_SHARED_DIR} / kClosedVector);
    REQUIRE(text);
    const json shared = json::parse(*text);

    // The same files, and but for the result's version the same bytes.
    const json& files = shared.at("files");
    CHECK(files.size() == 4);
    CHECK(files.at("items.csv") == made.at("files").at("items.csv"));
    CHECK(files.at("veeam-session.log") == "");
    json theirs = json::parse(files.at("result.json").get<std::string>());
    json ours = json::parse(made.at("files").at("result.json").get<std::string>());
    theirs.erase("worker_version");
    ours.erase("worker_version");
    CHECK(theirs == ours);
    CHECK(theirs.at("status") ==
          json{{"counts", {{"failed", 0}, {"items", 0}, {"unchecked", 0}, {"verified", 0}}},
               {"error_code", "interrupted"},
               {"failed_items", json::array()},
               {"message", "the run was interrupted before its result was written; a restore "
                           "request may have been sent, so items may be in the restore targets"},
               {"restore_sent", true},
               {"status", "error"},
               {"unchecked_items", json::array()},
               {"verified", {{"fields", 0}, {"manifest", 0}, {"metadata", 0}}},
               {"warnings", json::array()}});

    // The shared folder verifies as it is, under the key it names.
    std::map<std::string, std::string> folder;
    std::vector<std::string> names;
    for (const auto& [name, content] : files.items()) {
        folder[name] = content.get<std::string>();
        names.push_back(name);
    }
    const rp::FileReader read = [&folder](std::string_view name, std::uintmax_t) {
        rp::FileRead file;
        const auto found = folder.find(std::string{name});
        if (found != folder.end()) {
            file.state = rp::FileState::read;
            file.bytes = found->second;
        }
        return file;
    };
    const rp::Verification verified = rp::Signer::verify_folder(
        read, names, rp::test::public_key_of(rp::test::signing_key()));
    CHECK(rp::to_string(verified.word) == "verified");
    CHECK(verified.bundle_sha256 == shared.at("bundle_sha256").get<std::string>());
    CHECK(verified.key_id == shared.at("key_id").get<std::string>());
    CHECK(verified.timestamp == rp::TimestampState::none);
}
