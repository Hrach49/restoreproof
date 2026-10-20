// `rpworker outbox flush` and `rpworker outbox list` (rp/outbox_command.hpp;
// W4.6): their lines and exit codes, over temp folders, a FakeHttpClient in
// the Cloud's place, a fixed clock and a fake mutex. Failure paths first.

#include "fake_http_client.hpp"
#include "outbox_lab.hpp"
#include "restore_command_lab.hpp"

#include <rp/cli.hpp>
#include <rp/outbox_command.hpp>
#include <rp/vault.hpp>
#include <rp/run_lock.hpp>
#include <rp/timestamper.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <filesystem>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::EndsWith;
using Catch::Matchers::StartsWith;
using namespace rp::test::outbox_lab;

namespace {

using Args = std::vector<std::string_view>;
const std::string& kUsage = rp::test::restore_command_lab::kUsage;
const std::string kResultsUrl = "https://cloud.example.invalid/v1/results";
// A token of the Cloud's shape (W5.1), never a real one.
const std::string kToken = "FlushToke-w51-0123456789abcdefABCDEF_-01234";

struct Run {
    int exit_code;
    std::string out;
    std::string err;
};

struct FakeLock final : rp::RunLock {};

struct Lab {
    Lab()
    {
        config_path = box.dir.write(
            "config.json", rp::test::restore_command_lab::config_values().dump(2));
        cloud.on(rp::HttpMethod::post, kResultsUrl, {rp::test::cloud_answer(202)});
        secrets.cloud_api_token = kToken;
    }

    rp::OutboxCommandEnv env()
    {
        rp::OutboxCommandEnv env;
        env.default_config_path = [this] {
            ++default_config_calls;
            return config_path;
        };
        env.default_outbox_root = [this] {
            ++default_root_calls;
            return box.root;
        };
        env.make_cloud_http = [this](const rp::Config& config) -> std::unique_ptr<rp::IHttpClient> {
            cloud_ca_file = config.cloud_ca_file;
            if (no_http) {
                return nullptr;
            }
            return std::make_unique<rp::test::ForwardingHttpClient>(cloud);
        };
        env.wall_now = [this] { return at(now); };
        env.take_flush_lock = [this]() -> std::unique_ptr<rp::RunLock> {
            ++lock_calls;
            if (lock_abandoned && lock_calls == 1) {
                throw rp::AbandonedRunLock();
            }
            if (lock_taken) {
                return nullptr;
            }
            return std::make_unique<FakeLock>();
        };
        env.files = box.files;
        env.default_vault_path = [this] {
            ++default_vault_calls;
            return vault;
        };
        env.load_secrets = [this](const std::filesystem::path& file) {
            vault_read = file;
            if (vault_fails) {
                throw rp::VaultError(file.string() + ": vault file not found");
            }
            return secrets;
        };
        return env;
    }

    Run run(const Args& args)
    {
        std::ostringstream out;
        std::ostringstream err;
        const int code = rp::run_outbox_command(args, out, err, env());
        return {code, out.str(), err.str()};
    }

    Box box;
    std::filesystem::path config_path;
    rp::test::FakeHttpClient cloud;
    std::optional<std::string> cloud_ca_file;
    long long now = 0;
    bool no_http = false;
    bool lock_taken = false;
    bool lock_abandoned = false;
    int lock_calls = 0;
    int default_config_calls = 0;
    int default_root_calls = 0;
    // W5.1: the vault the flush reads its API token from.
    std::filesystem::path vault = box.dir.path() / "vault.bin";
    std::optional<std::filesystem::path> vault_read;
    rp::Secrets secrets;
    bool vault_fails = false;
    int default_vault_calls = 0;
};

} // namespace

// --- usage ----------------------------------------------------------------------------

TEST_CASE("rpworker outbox: a command line it doesn't understand is the usage line, exit 64",
          "[outbox_command]")
{
    const Args args = GENERATE(Args{}, Args{"send"}, Args{"flush", "now"},
                               Args{"flush", "--outbox"}, Args{"flush", "--outbox", ""},
                               Args{"flush", "--config", ""}, Args{"flush", "--record", ""},
                               Args{"flush", "--outbox", "a", "--outbox", "b"},
                               Args{"flush", "--vault", ""}, Args{"list", "--vault", "v.bin"},
                               Args{"list", "--config", "c.json"},
                               Args{"list", "--record", "rec"}, Args{"list", "--outbox", ""},
                               Args{"list", "extra"}, Args{"list", "flush"});
    Lab lab;
    lab.box.queue_run("run-0001");

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::usage);
    CHECK(run.out.empty());
    CHECK(run.err == kUsage);
    CHECK(lab.cloud.requests().empty());
    CHECK(lab.lock_calls == 0);
}

// --- flush: what stops it before anything is done -------------------------------------

TEST_CASE("rpworker outbox flush: a config that doesn't load, or a path that isn't UTF-8, is a "
          "config error before anything is sent",
          "[outbox_command][flush]")
{
    Lab lab;
    lab.box.queue_run("run-0001");
    const std::string what = GENERATE("no config", "--config", "--outbox", "--record");
    CAPTURE(what);
    const std::string bad = "bad-\xff";
    Args args{"flush"};
    std::string expected;
    if (what == "no config") {
        std::filesystem::remove(lab.config_path);
        expected = "config error: " + utf8_of(lab.config_path) + ": cannot read config file\n";
    } else {
        args.push_back(what);
        args.push_back(bad);
        expected = "config error: the " + what + " path is not valid UTF-8\n";
    }

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == expected);
    CHECK(lab.cloud.requests().empty());
    CHECK(std::filesystem::exists(lab.box.queued("run-0001") / "result.json"));
}

TEST_CASE("rpworker outbox flush: a --record folder that isn't empty is refused before anything "
          "is sent",
          "[outbox_command][flush][record]")
{
    Lab lab;
    lab.box.queue_run("run-0001");
    const std::string record = utf8_of(lab.box.dir.write("rec.txt", "x").parent_path());

    const Run run = lab.run({"flush", "--record", record});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK_THAT(run.err, StartsWith("config error: "));
    CHECK(lab.cloud.requests().empty());
}

TEST_CASE("rpworker outbox flush: another flush running is exit 3 and nothing is done",
          "[outbox_command][flush]")
{
    Lab lab;
    lab.box.queue_run("run-0001");
    lab.lock_taken = true;
    const std::filesystem::path record = lab.box.dir.path() / "rec";
    const std::string record_arg = utf8_of(record);

    const Run run = lab.run({"flush", "--record", record_arg});

    CHECK(run.exit_code == rp::exit_code::transient);
    CHECK(run.out.empty());
    CHECK(run.err == "outbox error: another flush is running; nothing was done\n");
    CHECK(lab.cloud.requests().empty());
    CHECK(lab.box.manifest_of(lab.box.queued("run-0001")).attempts == 0);
    CHECK_FALSE(std::filesystem::exists(record));
}

TEST_CASE("rpworker outbox flush: a mutex a dead flush left is taken at the second try",
          "[outbox_command][flush]")
{
    Lab lab;
    lab.box.queue_run("run-0001");
    lab.lock_abandoned = true;

    const Run run = lab.run({"flush"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.out == "sent run-0001\n0 queued, 1 sent, 0 failed\n");
    CHECK(lab.lock_calls == 2);
}

TEST_CASE("rpworker outbox flush: a root that can't be read is exit 1 with no count",
          "[outbox_command][flush]")
{
    Lab lab;
    std::filesystem::create_directories(lab.box.root);
    spit(lab.box.root / "outbox", "a file");

    const Run run = lab.run({"flush"});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "outbox error: " + utf8_of(lab.box.root) + ": the outbox can't be read\n");
    CHECK(lab.cloud.requests().empty());
}

TEST_CASE("rpworker outbox flush: no HTTP client is an unexpected failure, not an attempt",
          "[outbox_command][flush]")
{
    Lab lab;
    const std::filesystem::path folder = lab.box.queue_run("run-0001");
    lab.no_http = true;
    std::ostringstream out;
    std::ostringstream err;
    const Args args{"flush"};

    CHECK_THROWS_AS(rp::run_outbox_command(args, out, err, lab.env()), std::logic_error);
    CHECK(lab.box.manifest_of(folder).attempts == 0);
}

TEST_CASE("rpworker outbox is one of run_cli's commands", "[outbox_command][cli]")
{
    const Args args{"outbox", "flush", "--config", "no-such-config.json"};
    std::ostringstream out;
    std::ostringstream err;

    CHECK(rp::run_cli(args, out, err) == rp::exit_code::config);
    CHECK(out.str().empty());
    CHECK(err.str() == "config error: no-such-config.json: cannot read config file\n");
}

// --- flush: the network down, then up -------------------------------------------------

TEST_CASE("rpworker outbox flush --now sends a run whose next attempt hasn't come",
          "[outbox_command][flush]")
{
    // The uninstall's last flush: the outbox is deleted after it, so a run in its backoff is
    // tried once more rather than destroyed unsent (the W7.3 review's second pass).
    Lab lab;
    lab.box.queue_run("run-0001");
    int calls = 0;
    lab.cloud.on(rp::HttpMethod::post, kResultsUrl, [&calls](const rp::HttpRequest&) -> rp::HttpResponse {
        if (++calls == 1) {
            throw rp::HttpError("POST: could not connect", rp::TransportError::connect, 0, 1);
        }
        return rp::test::cloud_answer(202);
    });
    REQUIRE(lab.run({"flush"}).exit_code == rp::exit_code::transient);

    lab.now = 10;
    const Run early = lab.run({"flush"});
    CHECK(early.out == "waiting run-0001: next at " + text_at(60) + "\n1 queued, 0 sent, 0 failed\n");
    CHECK(calls == 1);

    const Run now = lab.run({"flush", "--now"});
    CHECK(now.exit_code == rp::exit_code::ok);
    CHECK(now.out == "sent run-0001\n0 queued, 1 sent, 0 failed\n");
    CHECK(now.err.empty());
    CHECK(calls == 2);

    // A flag, never a value; given twice it is usage.
    CHECK(lab.run({"flush", "--now", "--now"}).exit_code == rp::exit_code::usage);
}

TEST_CASE("rpworker outbox flush: with the Cloud down the run stays queued, exit 3; the next "
          "flush that reaches it sends it, exit 0",
          "[outbox_command][flush][acceptance]")
{
    Lab lab;
    const std::filesystem::path folder = lab.box.queue_run("run-0001");
    const auto before = files_of(folder);
    int calls = 0;
    lab.cloud.on(rp::HttpMethod::post, kResultsUrl,
                 [&calls](const rp::HttpRequest&) -> rp::HttpResponse {
                     ++calls;
                     if (calls == 1) {
                         throw rp::HttpError("POST: could not connect", rp::TransportError::connect,
                                             0, 1);
                     }
                     if (calls == 2) {
                         // The connection lost in the middle of the body.
                         throw rp::HttpError("POST: dropped", rp::TransportError::dropped, 0, 1);
                     }
                     if (calls == 3) {
                         return rp::test::make_response(500, "busy", "text/plain");
                     }
                     return rp::test::cloud_answer(202);
                 });

    const Run down = lab.run({"flush"});
    CHECK(down.exit_code == rp::exit_code::transient);
    CHECK(down.out == "kept run-0001: upload_unreachable; attempt 1, next at " + text_at(60) +
                          "\n1 queued, 0 sent, 0 failed\n");
    CHECK(down.err.empty());

    // Not due yet: nothing is sent.
    lab.now = 59;
    const Run early = lab.run({"flush"});
    CHECK(early.exit_code == rp::exit_code::transient);
    CHECK(early.out == "waiting run-0001: next at " + text_at(60) + "\n1 queued, 0 sent, 0 failed\n");
    CHECK(lab.cloud.requests().size() == 1);

    lab.now = 60;
    const Run dropped = lab.run({"flush"});
    CHECK(dropped.exit_code == rp::exit_code::transient);
    CHECK(dropped.out == "kept run-0001: upload_unreachable; attempt 2, next at " + text_at(180) +
                             "\n1 queued, 0 sent, 0 failed\n");
    CHECK(files_of(folder) == before);

    lab.now = 180;
    const Run busy = lab.run({"flush"});
    CHECK(busy.exit_code == rp::exit_code::transient);
    CHECK(busy.out == "kept run-0001: upload_http_500; attempt 3, next at " + text_at(420) +
                          "\n1 queued, 0 sent, 0 failed\n");

    lab.now = 420;
    const Run sent = lab.run({"flush"});
    CHECK(sent.exit_code == rp::exit_code::ok);
    CHECK(sent.out == "sent run-0001\n0 queued, 1 sent, 0 failed\n");
    CHECK(sent.err.empty());
    CHECK(files_of(lab.box.sent("run-0001")) == before);
    CHECK(lab.box.manifest_of(lab.box.sent("run-0001")).attempts == 4);

    // What went out the last time: the five parts, to cloud_url's /v1/results.
    const std::vector<rp::HttpRequest> requests = lab.cloud.requests();
    REQUIRE(requests.size() == 4);
    CHECK(requests.back().url == kResultsUrl);
    REQUIRE(requests.back().parts.size() == 5);
    CHECK(requests.back().parts[0].name == "result");
    CHECK(requests.back().parts[0].content == before.at("result.json"));
    // W5.1: the API token, and nothing else.
    CHECK(requests.back().headers == rp::HttpHeaders{{"Authorization", "Bearer " + kToken}});
    CHECK(lab.default_config_calls == 5);
    CHECK(lab.default_root_calls == 5);
}

TEST_CASE("rpworker outbox flush: an outbox error with nothing left queued is exit 1; with a run "
          "left it is 3",
          "[outbox_command][flush]")
{
    Lab lab;
    const bool with_run = GENERATE(false, true);
    std::filesystem::create_directories(lab.box.queued("stray"));
    if (with_run) {
        const std::filesystem::path folder = lab.box.queue_run("run-0001");
        spit(folder / "items.csv", "changed");
    }

    const Run run = lab.run({"flush"});

    const std::string stray = "outbox error: " + utf8_of(lab.box.queued("stray")) +
                              ": no result.json; not a queued run\n";
    if (with_run) {
        CHECK(run.exit_code == rp::exit_code::transient);
        CHECK(run.out == "kept run-0001: folder_changed\n1 queued, 0 sent, 0 failed\n");
        CHECK(run.err == stray + "outbox error: " + utf8_of(lab.box.queued("run-0001")) +
                             ": items.csv changed since it was signed\n");
    } else {
        CHECK(run.exit_code == rp::exit_code::config);
        CHECK(run.out == "0 queued, 0 sent, 0 failed\n");
        CHECK(run.err == stray);
    }
    CHECK(lab.cloud.requests().empty());
}

TEST_CASE("rpworker outbox flush: --config and --outbox name the config and the root, a warning "
          "changes no exit code, and cloud_ca_file reaches the client's maker",
          "[outbox_command][flush]")
{
    Lab lab;
    const std::filesystem::path other_root = lab.box.dir.path() / "elsewhere";
    const std::filesystem::path ca =
        lab.box.dir.write("cloud-ca.pem", std::string{rp::default_tsa_ca_pem()});
    nlohmann::json config = rp::test::restore_command_lab::config_values();
    config["cloud_url"] = "https://cloud.example.invalid/";
    config["cloud_ca_file"] = utf8_of(ca);
    const std::string config_arg = utf8_of(lab.box.dir.write("other.json", config.dump()));
    const std::string root_arg = utf8_of(other_root);
    Box other;
    other.root = other_root;
    other.runs = lab.box.runs;
    const std::filesystem::path folder = other.queue_run("run-0002", 0, false);
    std::filesystem::remove(folder / "manifest.json");
    other.sent_run("old", -40LL * 24 * 3600);

    const Run run = lab.run({"flush", "--outbox", root_arg, "--config", config_arg});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.out == "pruned old\nsent run-0002\n0 queued, 1 sent, 0 failed\n");
    CHECK(run.err == "outbox warning: " + utf8_of(folder) + ": manifest.json was made again\n");
    CHECK(lab.cloud_ca_file == utf8_of(ca));
    CHECK(lab.default_config_calls == 0);
    CHECK(lab.default_root_calls == 0);
    CHECK(lab.cloud.requests().size() == 1);
}

TEST_CASE("rpworker outbox flush --record: the exchange is the recording's cloud folder, the "
          "answer only, and replays",
          "[outbox_command][flush][record]")
{
    Lab lab;
    lab.box.queue_run("run-0001");
    const std::filesystem::path recording = lab.box.dir.path() / "rec";
    const std::string record_arg = utf8_of(recording);

    const Run run = lab.run({"flush", "--record", record_arg});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK(run.out == "sent run-0001\n0 queued, 1 sent, 0 failed\nrecorded 1 exchange(s) in " + record_arg +
                         "\n");
    const std::optional<std::string> text = slurp(recording / "cloud" / "001-post-v1-results.json");
    REQUIRE(text);
    const nlohmann::json fixture = nlohmann::json::parse(*text);
    CHECK(fixture.at("request") == "POST /v1/results");
    CHECK(fixture.at("status") == 202);
    // No part of the upload is in it: a multipart body is never written.
    CHECK_FALSE(fixture.contains("request_body"));
    CHECK_THAT(*text, !ContainsSubstring("run-0001"));
    CHECK_THAT(*text, !ContainsSubstring("bundle_sha256"));

    // The recording answers the next run's upload.
    Lab replay;
    replay.box.queue_run("run-0002");
    rp::test::FakeHttpClient recorded;
    REQUIRE(recorded.serve_recording(recording / "cloud") == 1);
    rp::OutboxCommandEnv env = replay.env();
    env.make_cloud_http = [&](const rp::Config&) -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(recorded);
    };
    std::ostringstream out;
    std::ostringstream err;
    const Args args{"flush"};
    CHECK(rp::run_outbox_command(args, out, err, env) == rp::exit_code::ok);
    CHECK(out.str() == "sent run-0002\n0 queued, 1 sent, 0 failed\n");
}

// --- list -----------------------------------------------------------------------------

TEST_CASE("rpworker outbox list: an empty root is no table and two zeros", "[outbox_command][list]")
{
    Lab lab;

    const Run run = lab.run({"list"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.out == "0 queued, 0 sent, 0 failed\n");
    CHECK(run.err.empty());
    CHECK(lab.default_root_calls == 1);
    CHECK(lab.default_config_calls == 0);
    CHECK(lab.lock_calls == 0);
    CHECK_FALSE(std::filesystem::exists(lab.box.root));
}

TEST_CASE("rpworker outbox list: a root that can't be read, or a path that isn't UTF-8, is exit 1",
          "[outbox_command][list]")
{
    Lab lab;
    SECTION("sent is a file")
    {
        std::filesystem::create_directories(lab.box.root);
        spit(lab.box.root / "sent", "a file");
        const Run run = lab.run({"list"});
        CHECK(run.exit_code == rp::exit_code::config);
        CHECK(run.out.empty());
        CHECK(run.err == "outbox error: " + utf8_of(lab.box.root) + ": the outbox can't be read\n");
    }
    SECTION("--outbox isn't UTF-8")
    {
        const Run run = lab.run({"list", "--outbox", "bad-\xff"});
        CHECK(run.exit_code == rp::exit_code::config);
        CHECK(run.out.empty());
        CHECK(run.err == "config error: the --outbox path is not valid UTF-8\n");
    }
}

TEST_CASE("rpworker outbox list: one row per queued run, then the counts; it changes nothing",
          "[outbox_command][list][acceptance]")
{
    Lab lab;
    const std::filesystem::path stamped = lab.box.queue_run("run-b", 10);
    lab.box.queue_run("run-a", 20, false);
    const std::filesystem::path coded = lab.box.queue_run("run-d", 40, false);
    const std::filesystem::path bare = lab.box.queue_run("run-c", 30);
    std::filesystem::remove(bare / "manifest.json");
    std::filesystem::create_directories(lab.box.queued("stray"));
    lab.box.sent_run("old", -50);
    // One failed attempt on run-b; run-d got no token and no code.
    rp::OutboxManifest manifest = lab.box.manifest_of(stamped);
    manifest.attempts = 3;
    manifest.last_attempt_at = text_at(100);
    manifest.next_attempt_at = text_at(340);
    manifest.last_error = "upload_http_503";
    spit(stamped / "manifest.json", rp::manifest_text(manifest));
    rp::OutboxManifest no_code = lab.box.manifest_of(coded);
    no_code.timestamp_code.reset();
    spit(coded / "manifest.json", rp::manifest_text(no_code));
    const std::string root_arg = utf8_of(lab.box.root);

    const Run run = lab.run({"list", "--outbox", root_arg});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.out ==
          "RUN    QUEUED                ATTEMPTS  NEXT                  LAST_ERROR       TIMESTAMP\n"
          "run-a  2026-10-07T12:00:20Z  0         -                     -                not_timestamped tsa_unreachable\n"
          "run-b  2026-10-07T12:00:10Z  3         2026-10-07T12:05:40Z  upload_http_503  timestamped\n"
          "run-c  -                     -         -                     no_manifest      -\n"
          "run-d  2026-10-07T12:00:40Z  0         -                     -                not_timestamped\n"
          "4 queued, 1 sent, 0 failed\n");
    CHECK(run.err == "outbox error: " + utf8_of(lab.box.queued("stray")) +
                         ": no result.json; not a queued run\n");
    CHECK(lab.default_root_calls == 0);
    CHECK_FALSE(std::filesystem::exists(bare / "manifest.json"));
    CHECK(lab.cloud.requests().empty());
}

TEST_CASE("the outbox's default root is RestoreProof under ProgramData, and the real environment "
          "names it and the default config",
          "[outbox_command]")
{
    CHECK(rp::default_outbox_root() == rp::program_data_dir() / "RestoreProof");
    const rp::OutboxCommandEnv env = rp::default_outbox_command_env();
    CHECK(env.default_outbox_root() == rp::default_outbox_root());
    CHECK(env.default_config_path() == rp::default_config_path());
    CHECK_FALSE(env.make_cloud_http);
    CHECK_FALSE(env.wall_now);
    CHECK_FALSE(env.take_flush_lock);
}


// --- W5.1: the API token and the Cloud's answers (docs/decisions.md 2026-10-15, point 8) ---

TEST_CASE("outbox flush: without the API token in the vault nothing is tried", "[outbox_command][w51]")
{
    Lab lab;
    const path folder = lab.box.queue_run("run-0001");
    const bool fails = GENERATE(false, true);
    if (fails) {
        lab.vault_fails = true;
    } else {
        lab.secrets.cloud_api_token.reset();
    }

    const Run run = lab.run({"flush"});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == (fails ? "config error: " + lab.vault.string() + ": vault file not found\n"
                            : std::string{"outbox error: cloud_api_token is not in the vault; nothing "
                                          "was sent (rpworker cloud register)\n"}));
    CHECK(lab.cloud.requests().empty());
    CHECK(lab.box.manifest_of(folder).attempts == 0);
    CHECK(lab.lock_calls == 0);
}

TEST_CASE("outbox flush: the upload carries the vault's API token; --vault names the vault",
          "[outbox_command][w51]")
{
    Lab lab;
    lab.box.queue_run("run-0001");
    const std::string vault_arg = (lab.box.dir.path() / "other.bin").string();

    const Run run = lab.run({"flush", "--vault", vault_arg});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.out == "sent run-0001\n0 queued, 1 sent, 0 failed\n");
    CHECK(lab.vault_read == std::filesystem::path{vault_arg});
    CHECK(lab.default_vault_calls == 0);
    REQUIRE(lab.cloud.requests().size() == 1);
    CHECK(lab.cloud.requests()[0].headers.at("Authorization") == "Bearer " + kToken);
    CHECK_THAT(run.out + run.err, !ContainsSubstring(kToken));

    Lab plain;
    plain.box.queue_run("run-0001");
    CHECK(plain.run({"flush"}).exit_code == rp::exit_code::ok);
    CHECK(plain.default_vault_calls == 1);
    CHECK(plain.vault_read == plain.vault);
}

TEST_CASE("outbox flush: a refusal for good moves the run to failed and exits 1", "[outbox_command][w51]")
{
    Lab lab;
    lab.box.queue_run("run-0001");
    lab.cloud.on(rp::HttpMethod::post, kResultsUrl, {rp::test::load_fixture("cloud", "results/409-not-dispatched")});

    const Run run = lab.run({"flush"});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out == "failed run-0001: upload_http_409\n0 queued, 0 sent, 1 failed\n");
    CHECK(run.err == "outbox error: run-0001: refused by the Cloud (upload_http_409); moved to failed\n");
    CHECK(std::filesystem::exists(lab.box.refused("run-0001") / "result.json"));
}

TEST_CASE("outbox flush: the operator's flush tries a run a 401 kept at once", "[outbox_command][w51]")
{
    Lab lab;
    lab.box.queue_run("run-0001");
    lab.cloud.on(rp::HttpMethod::post, kResultsUrl,
                 {rp::test::load_fixture("cloud", "results/401"), rp::test::cloud_answer(202)});

    const Run first = lab.run({"flush"});
    CHECK(first.exit_code == rp::exit_code::transient);
    CHECK(first.out == "kept run-0001: upload_http_401; attempt 1, next at " + text_at(60) +
                           "\n1 queued, 0 sent, 0 failed\n");

    lab.now = 1;
    const Run second = lab.run({"flush"});
    CHECK(second.exit_code == rp::exit_code::ok);
    CHECK(second.out == "sent run-0001\n0 queued, 1 sent, 0 failed\n");
}

TEST_CASE("outbox flush: a 202 that isn't the Cloud's is no send", "[outbox_command][w51]")
{
    Lab lab;
    lab.box.queue_run("run-0001");
    lab.cloud.on(rp::HttpMethod::post, kResultsUrl, {rp::test::load_fixture("cloud", "results/502-proxy"),
                                                     rp::test::make_response(202)});

    CHECK(lab.run({"flush"}).out ==
          "kept run-0001: upload_http_502; attempt 1, next at " + text_at(60) + "\n1 queued, 0 sent, 0 failed\n");
    lab.now = 100;
    CHECK(lab.run({"flush"}).out == "kept run-0001: upload_not_cloud; attempt 2, next at " + text_at(220) +
                                        "\n1 queued, 0 sent, 0 failed\n");
}

TEST_CASE("outbox list: the count line names the runs under failed", "[outbox_command][w51]")
{
    Lab lab;
    std::filesystem::create_directories(lab.box.refused("run-0009"));

    const Run run = lab.run({"list"});
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.out == "0 queued, 0 sent, 1 failed\n");
}

TEST_CASE("outbox flush --record writes no token", "[outbox_command][w51]")
{
    Lab lab;
    lab.box.queue_run("run-0001");
    const std::filesystem::path recording = lab.box.dir.path() / "rec";
    const std::string recording_arg = recording.string();

    const Run run = lab.run({"flush", "--record", recording_arg});

    CHECK(run.exit_code == rp::exit_code::ok);
    for (const auto& entry : std::filesystem::recursive_directory_iterator(recording)) {
        if (entry.is_regular_file()) {
            CHECK_THAT(slurp(entry.path()).value_or(""), !ContainsSubstring(kToken));
        }
    }
}
