// W4.9 (#52): the secret audit (docs/decisions.md 2026-10-09). Every path of
// the pipeline, the commands that read the vault and the service's loop runs
// on fixtures with five sentinel secrets (tests/secret_audit_lab.hpp), and
// everything each path wrote (both streams, the logger, a real worker.log,
// every file under the temp folder, every request the fake Cloud and the
// fake TSA received) is searched for every sentinel, every value derived from
// one (the PFX's bytes and hex, the signing seed's two shapes, the tokens the
// fakes hand out, the exported credential, the client assertion the run
// signed) and every secret shape. A hit fails the case, naming the output and
// the secret's label, never its bytes. Each case REQUIREs its own expected
// line or file first, so an audit over nothing can't pass. No network, no
// sleep, no vault but a DPAPI one in the temp folder, nothing under
// %ProgramData%.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "outbox_lab.hpp"
#include "replay_lab.hpp"
#include "restore_command_lab.hpp"
#include "secret_audit_lab.hpp"
#include "signing_lab.hpp"
#include "veeam_restore_lab.hpp"
#include "worker_body_lab.hpp"

#include <rp/cli.hpp>
#include <rp/client_command.hpp>
#include <rp/client_profile.hpp>
#include <rp/cloud_command.hpp>
#include <rp/connector.hpp>
#include <rp/graph_command.hpp>
#include <rp/outbox_command.hpp>
#include <rp/service_log.hpp>
#include <rp/service_recovery.hpp>
#include <rp/base64.hpp>
#include <rp/signer.hpp>
#include <rp/signer_command.hpp>
#include <rp/test_command.hpp>
#include <rp/vault.hpp>
#include <rp/vault_command.hpp>
#include <rp/veeam_command.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <filesystem>
#include <span>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

using Catch::Matchers::ContainsSubstring;

namespace {

using namespace rp::test::restore_command_lab;
using namespace rp::test::worker_body_lab;
namespace audit = rp::test::secret_audit;
namespace gl = rp::test::graph_lab;
namespace replay_lab = rp::test::replay_lab;
namespace vrl = rp::test::veeam_restore_lab;

// The Harness with the audit's secrets and tokens, and the collector.
struct AuditLab : Harness {
    AuditLab()
    {
        load_secrets = audit::secrets;
        targets.graph.on(rp::HttpMethod::post, gl::kTokenUrl, {audit::graph_token_response()});
        fake.pool.mail = {carol_mail(1)};
    }

    audit::SecretSet searched = audit::searched();
    audit::Outputs outputs;

    // The arguments as strings that outlive the Args (string_views) made of them.
    const std::string evidence_arg = utf8(dir.path() / "runs");
    const std::string outbox_arg = utf8(dir.path() / "box");

    void collect(std::string_view label, const Run& run)
    {
        outputs.add(std::string{label} + " stdout", run.out);
        outputs.add(std::string{label} + " stderr", run.err);
    }

    // The logger's text, every file under the temp folder, the TSA's requests
    // and the client assertions the run signed; then the search.
    void finish()
    {
        outputs.add("logger", log());
        outputs.add_folder(dir.path(), "temp");
        outputs.add_requests("tsa", tsa_http);
        audit::add_client_assertions(searched, targets.graph);
        audit::expect_clean(searched, outputs);
    }
};

const Args kThree{"--mail", "2", "--sp", "1", "--od", "0"};

Args with_run_id(std::string_view run_id, Args args = kThree)
{
    args.insert(args.begin(), {"--run-id", run_id});
    return args;
}

// The profile a job would carry, written as a file from the config's eight
// client keys (W4.10): the file's path, for --profile-file.
std::string write_profile(AuditLab& lab)
{
    json profile = {{"format", std::string{rp::kClientProfileFormat}}};
    const json config_doc = json::parse(file_bytes(lab.config_path).value());
    for (const std::string_view key : rp::kClientProfileKeys) {
        profile[std::string{key}] = config_doc.at(key);
    }
    return utf8(lab.dir.write("profile.json", profile.dump(2)));
}

} // namespace

// --- the shapes: the fixture scan's cases, which the C++ side is held to too -----------

TEST_CASE("secret audit: the shapes are the fixture scan's, on its shared cases", "[secret_audit]")
{
    const std::filesystem::path file =
        std::filesystem::path{RP_SOURCE_DIR} / "tools" / "secret_shapes_cases.json";
    const std::optional<std::string> text = file_bytes(file);
    REQUIRE(text);
    const json cases = json::parse(*text);
    std::size_t shaped = 0;
    for (const json& c : cases.at("shaped")) {
        const std::string shape = c.at("shape").get<std::string>();
        if (shape == "keyed_secret") {
            continue; // the values' own rule here; the scan's keyed rule has no C++ twin
        }
        const std::string example = c.at("text").get<std::string>();
        CAPTURE(shape, example);
        bool found = false;
        for (const audit::ShapeHit& hit : audit::shapes_in(example)) {
            found = found || hit.shape == shape;
        }
        CHECK(found);
        ++shaped;
    }
    CHECK(shaped >= 20);
    for (const json& c : cases.at("clean")) {
        const std::string example = c.get<std::string>();
        CAPTURE(example);
        CHECK(audit::shapes_in(example).empty());
    }
}

// --- A to H: the pipeline ------------------------------------------------------------

TEST_CASE("secret audit A: rpworker restore --profile-file, a pass; a profile file that is no "
          "profile",
          "[secret_audit]")
{
    AuditLab lab;
    // W4.10: the run's client read from a profile file, as a job's would be.
    const std::string profile_file = write_profile(lab);
    Args args = with_run_id("audit-a");
    args.insert(args.end(), {"--profile-file", profile_file});

    const Run run = lab.run(args);

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(run.out, ContainsSubstring("\nstatus pass: "));
    lab.collect("restore --profile-file", run);

    // And the refusal: a file that is no profile ends the command before the
    // vault is read, its one line naming the file and never a value of it.
    const std::string broken =
        utf8(lab.dir.write("broken-profile.json", R"({"format":"restoreproof.client-profile.v1"})"));
    Args refused_args = with_run_id("audit-a-refused");
    refused_args.insert(refused_args.end(), {"--profile-file", broken});
    const Run refused = lab.run(refused_args);
    INFO(refused.err);
    REQUIRE(refused.exit_code == rp::exit_code::config);
    REQUIRE_THAT(refused.err, ContainsSubstring("config error: --profile-file "));
    lab.collect("restore --profile-file, refused", refused);
    lab.finish();
    CHECK(lab.outputs.has_output("temp/profile.json"));
    // The run signed in to Graph: the assertion was searched for.
    CHECK(audit::client_assertions_in(lab.targets.graph).size() >= 1);
}

TEST_CASE("secret audit B: rpworker test --json", "[secret_audit]")
{
    AuditLab lab;
    lab.command = rp::run_test_command;
    const std::string json_file = utf8(lab.dir.path() / "run.json");
    Args args = with_run_id("audit-b");
    args.insert(args.end(), {"--json", json_file});

    const Run run = lab.run(args);

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    REQUIRE(std::filesystem::exists(lab.dir.path() / "run.json"));
    lab.collect("test --json", run);
    lab.finish();
    CHECK(lab.outputs.has_output("temp/run.json"));
}

TEST_CASE("secret audit C: test --evidence --outbox --record, a pass; outbox flush with the Cloud "
          "refusing and then taking it; outbox list; graph list --hash --record; client check "
          "--profile-file --record",
          "[secret_audit]")
{
    AuditLab lab;
    lab.command = rp::run_test_command;
    const std::string record = utf8(lab.dir.path() / "rec");
    Args args = with_run_id("audit-c");
    args.insert(args.end(), {"--evidence", lab.evidence_arg, "--outbox", lab.outbox_arg,
                             "--record", record});

    const Run run = lab.run(args);

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(run.out, ContainsSubstring("\nstatus pass: "));
    REQUIRE_THAT(run.out, ContainsSubstring("\nsigned "));
    REQUIRE_THAT(run.out, ContainsSubstring("\ntimestamped "));
    REQUIRE_THAT(run.out, ContainsSubstring("\nqueued "));
    REQUIRE_THAT(run.out, ContainsSubstring("\nrecorded "));
    lab.collect("test --evidence --outbox --record", run);

    // The flush: the Cloud answers 500, then 202.
    rp::test::FakeHttpClient cloud;
    int calls = 0;
    cloud.on(rp::HttpMethod::post, "https://cloud.example.invalid/v1/results",
             [&calls](const rp::HttpRequest&) {
                 return rp::test::cloud_answer(++calls == 1 ? 500 : 202);
             });
    long long now = 0;
    rp::OutboxCommandEnv env;
    env.default_config_path = [&] { return lab.config_path; };
    env.default_outbox_root = [&] { return lab.dir.path() / "box"; };
    env.make_cloud_http = [&](const rp::Config&) -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(cloud);
    };
    env.wall_now = [&] { return rp::test::outbox_lab::at(now); };
    env.take_flush_lock = []() -> std::unique_ptr<rp::RunLock> {
        struct Lock final : rp::RunLock {};
        return std::make_unique<Lock>();
    };
    // W5.1: the flush reads the API token from the audit's vault.
    env.default_vault_path = [&] { return lab.dir.path() / "vault.bin"; };
    env.load_secrets = [](const std::filesystem::path&) { return audit::secrets(); };
    const auto outbox = [&](const Args& words) {
        std::ostringstream out;
        std::ostringstream err;
        const int code = rp::run_outbox_command(words, out, err, env);
        return Run{code, out.str(), err.str()};
    };
    // Each flush with --record: the Cloud's answers, under cloud/.
    const std::string refused_record = utf8(lab.dir.path() / "rec-flush-refused");
    const std::string sent_record = utf8(lab.dir.path() / "rec-flush-sent");
    const Run refused = outbox({"flush", "--record", refused_record});
    REQUIRE(refused.exit_code == rp::exit_code::transient);
    REQUIRE_THAT(refused.out, ContainsSubstring("kept audit-c: upload_http_500; attempt 1"));
    REQUIRE_THAT(refused.out, ContainsSubstring("recorded "));
    now = 60;
    const Run sent = outbox({"flush", "--record", sent_record});
    REQUIRE(sent.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(sent.out, ContainsSubstring("sent audit-c\n"));
    REQUIRE_THAT(sent.out, ContainsSubstring("recorded "));
    const Run listed = outbox({"list"});
    REQUIRE(listed.exit_code == rp::exit_code::ok);
    lab.collect("outbox flush (refused)", refused);
    lab.collect("outbox flush (sent)", sent);
    lab.collect("outbox list", listed);
    lab.outputs.add_requests("cloud", cloud, "Bearer " + std::string{audit::kApiToken});

    // graph list --hash --record on the same targets, which hold the run's
    // copies the clean after didn't take (the fake lists them still).
    rp::GraphCommandEnv graph_env;
    graph_env.default_config_path = [&] { return lab.config_path; };
    graph_env.default_vault_path = [&] { return lab.default_vault; };
    graph_env.load_secrets = [](const std::filesystem::path&) { return audit::secrets(); };
    graph_env.make_graph_http = [&](std::shared_ptr<spdlog::logger>) -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(lab.targets.graph);
    };
    graph_env.make_download_http = [&]() -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(lab.targets.download);
    };
    graph_env.client_options.logger = lab.logger;
    graph_env.client_options.wall_now = lab.wall_now;
    const std::string config = utf8(lab.config_path);
    const std::string graph_record = utf8(lab.dir.path() / "rec-graph");
    std::ostringstream out;
    std::ostringstream err;
    const Args graph_args{"list", "--hash", "--config", config, "--record", graph_record};
    const int code = rp::run_graph_command(graph_args, out, err, graph_env);
    const Run graph_list{code, out.str(), err.str()};
    REQUIRE(graph_list.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(graph_list.out, ContainsSubstring("recorded "));
    lab.collect("graph list --hash --record", graph_list);

    // W4.10: client check --profile-file --record on the same targets, the
    // profile a job would carry written as a file from the config's keys
    // (IDs, a name and an address: nothing in it is a secret value).
    const std::string profile_file = write_profile(lab);
    const std::string client_record = utf8(lab.dir.path() / "rec-client");
    std::ostringstream client_out;
    std::ostringstream client_err;
    const Args client_args{"check", "--profile-file", profile_file, "--record", client_record};
    const int client_code = rp::run_client_command(client_args, client_out, client_err, graph_env);
    const Run client_check{client_code, client_out.str(), client_err.str()};
    REQUIRE(client_check.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(client_check.out, ContainsSubstring("client profile: veeam_org_name "));
    REQUIRE_THAT(client_check.out, ContainsSubstring("recorded "));
    lab.collect("client check --profile-file --record", client_check);

    lab.finish();
    // The whole folder went through the outbox and was uploaded, part by part.
    CHECK(lab.outputs.has_output("temp/box/sent/audit-c/result.json"));
    CHECK(lab.outputs.has_output("temp/box/sent/audit-c/manifest.json"));
    CHECK(lab.outputs.has_output("temp/rec/graph/"));
    CHECK(lab.outputs.has_output("temp/rec-client/graph/"));
    CHECK(lab.outputs.has_output("temp/profile.json"));
    CHECK(lab.outputs.has_output("temp/rec/tsa/"));
    CHECK(lab.outputs.has_output("temp/rec-flush-refused/cloud/"));
    CHECK(lab.outputs.has_output("temp/rec-flush-sent/cloud/"));
    CHECK(lab.outputs.has_output("cloud request 2 part 1 content"));
    CHECK(lab.outputs.has_output("tsa request 1 body"));
}

TEST_CASE("secret audit D: a fail, an item missing from its target", "[secret_audit]")
{
    AuditLab lab;
    lab.command = rp::run_test_command;
    lab.targets.after[kind_slot(connector::ItemKind::sharepoint)] = json::array();
    Args args = with_run_id("audit-d");
    args.insert(args.end(), {"--evidence", lab.evidence_arg});

    const Run run = lab.run(args);

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::restore);
    REQUIRE_THAT(run.out, ContainsSubstring("\nstatus fail: "));
    lab.collect("test, a fail", run);
    lab.finish();
    CHECK(lab.outputs.has_output("temp/runs/audit-d/items.csv"));
}

TEST_CASE("secret audit E: an error before the restore, Graph refusing the token", "[secret_audit]")
{
    AuditLab lab;
    lab.command = rp::run_test_command;
    lab.targets.graph.on(rp::HttpMethod::post, gl::kTokenUrl,
                         {rp::test::load_fixture("graph", "token-bad-signature-401")});
    Args args = with_run_id("audit-e");
    args.insert(args.end(), {"--evidence", lab.evidence_arg});

    const Run run = lab.run(args);

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::auth);
    // W4.11: the client check signs in to Graph first, so it is where the
    // token is refused.
    REQUIRE_THAT(run.err, ContainsSubstring("client error: "));
    REQUIRE_THAT(run.out, ContainsSubstring("\nstatus error graph_auth: "));
    lab.collect("test, Graph refusing", run);
    lab.finish();
    CHECK(lab.outputs.has_output("temp/runs/audit-e/result.json"));
}

TEST_CASE("secret audit F: an error in the restore phase, the connector refused", "[secret_audit]")
{
    AuditLab lab;
    lab.command = rp::run_test_command;
    lab.fake.restore_throw = [] { throw connector::AuthError("Veeam refused the credentials"); };
    Args args = with_run_id("audit-f");
    args.insert(args.end(), {"--evidence", lab.evidence_arg});

    const Run run = lab.run(args);

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::auth);
    REQUIRE_THAT(run.err, ContainsSubstring("restore error: "));
    REQUIRE_THAT(run.out, ContainsSubstring("\nstatus error backup_auth: "));
    lab.collect("test, the connector refused", run);
    lab.finish();
}

TEST_CASE("secret audit H: the TSA failing", "[secret_audit]")
{
    AuditLab lab;
    lab.command = rp::run_test_command;
    lab.tsa_answer = [](const rp::HttpRequest&) { return rp::test::make_response(503); };
    Args args = with_run_id("audit-h");
    args.insert(args.end(), {"--evidence", lab.evidence_arg});

    const Run run = lab.run(args);

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(run.err, ContainsSubstring("timestamp warning: "));
    REQUIRE_THAT(run.out, ContainsSubstring("\nsigned "));
    lab.collect("test, the TSA down", run);
    lab.finish();
    CHECK(lab.outputs.has_output("temp/runs/audit-h/signature.json"));
    CHECK_FALSE(lab.outputs.has_output("temp/runs/audit-h/timestamp.tst"));
}

// --- I: the real connector over the recorded live run --------------------------------

TEST_CASE("secret audit I: the real veeam_m365 connector over the W3.4 live recording, the "
          "restore POSTs carrying the exported credential",
          "[secret_audit]")
{
    replay_lab::Replay replay("w34-live-run1", replay_lab::Cleanup::recorded);
    // The recording's account, so the duplicate check finds the recorded
    // sessions; the audit's four secret values.
    replay.load_secrets = [] {
        rp::Secrets secrets = audit::secrets();
        secrets.veeam_username = "AUDIT-HOST\\rp-veeam";
        return secrets;
    };
    replay.veeam.on(rp::HttpMethod::post, "https://localhost:4443/v8/token",
                    {audit::veeam_token_response()});
    replay.graph.on(rp::HttpMethod::post, gl::kTokenUrl, {audit::graph_token_response()});
    replay.exporter->pfx = audit::exported_pfx();
    replay.exporter->password = std::string{audit::kExportedPfxPassword};

    // --record: the one recording whose requests carry the exported
    // credential, the restore POSTs' own bodies.
    const std::filesystem::path record = replay.temp.path() / "rec";
    const std::u8string record_text = record.u8string();

    const replay_lab::Run run =
        replay.run(replay_lab::kW34Run, {"--record", {record_text.begin(), record_text.end()}});

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(run.out, ContainsSubstring("\nstatus pass: 11 of 11 item(s) verified"));
    REQUIRE_THAT(run.out, ContainsSubstring("\nrecorded "));
    REQUIRE(replay.exporter->calls == 4);
    // Each restore POST was recorded with its body, the credential's two
    // keys there and masked.
    std::size_t recorded_posts = 0;
    for (const std::filesystem::path& file : replay_lab::recorded_files(record / "veeam")) {
        const json fixture = json::parse(replay_lab::read_file(file));
        const std::string request = fixture.at("request").get<std::string>();
        if (!request.starts_with("POST ") ||
            !(request.ends_with("/restoreTo") || request.ends_with("/copyTo"))) {
            continue;
        }
        ++recorded_posts;
        REQUIRE(fixture.contains("request_body"));
        const std::string body = fixture.at("request_body").dump();
        CHECK_THAT(body, ContainsSubstring("applicationCertificate"));
        CHECK_THAT(body, ContainsSubstring("applicationCertificatePassword"));
    }
    CHECK(recorded_posts == 4);
    audit::SecretSet searched = audit::searched();
    audit::add_client_assertions(searched, replay.graph);
    audit::Outputs outputs;
    outputs.add("restore stdout", run.out);
    outputs.add("restore stderr", run.err);
    outputs.add("logger", replay.log());
    outputs.add_folder(replay.temp.path(), "temp");
    audit::expect_clean(searched, outputs);
    CHECK(outputs.has_output("temp/rec/veeam/"));
    CHECK(outputs.has_output("temp/rec/graph/"));
    // The exported credential went to Veeam, four times, and nowhere else.
    std::size_t posts_with_credential = 0;
    for (const rp::HttpRequest& request : replay.veeam.requests()) {
        if (request.body.find(audit::exported_pfx()) != std::string::npos) {
            ++posts_with_credential;
        }
    }
    CHECK(posts_with_credential == 4);
}

// --- G and J: the service's loop, its log a real worker.log -------------------------------

namespace {

struct ServiceAudit {
    BodyLab lab;
    std::shared_ptr<rp::ServiceLog> log;
    audit::SecretSet searched = audit::searched();
    audit::Outputs outputs;

    ServiceAudit()
    {
        lab.h.load_secrets = audit::secrets;
        lab.h.targets.graph.on(rp::HttpMethod::post, gl::kTokenUrl,
                               {audit::graph_token_response()});
        auto made = rp::make_service_logger(lab.h.dir.path() / "logs", spdlog::level::trace,
                                            rp::LogLimits{1024 * 1024, 5});
        REQUIRE(std::holds_alternative<std::shared_ptr<rp::ServiceLog>>(made));
        log = std::get<std::shared_ptr<rp::ServiceLog>>(made);
        lab.context->logger = log->logger();
    }

    std::string log_text()
    {
        log->flush();
        const std::optional<std::string> text = file_bytes(lab.h.dir.path() / "logs" / "worker.log");
        REQUIRE(text);
        return *text;
    }

    void finish()
    {
        log->flush();
        log->close();
        outputs.add_folder(lab.h.dir.path(), "temp");
        outputs.add_requests("cloud", lab.cloud, "Bearer " + std::string{audit::kApiToken});
        outputs.add_requests("tsa", lab.h.tsa_http);
        audit::add_client_assertions(searched, lab.h.targets.graph);
        audit::expect_clean(searched, outputs);
        CHECK(outputs.has_output("temp/logs/worker.log"));
    }
};

} // namespace

TEST_CASE("secret audit G: a run that ends result_invalid, closed afterwards by the service as "
          "error result_invalid",
          "[secret_audit]")
{
    ServiceAudit audit;
    // W4.11: the schema holds the type to the registry's name rule; a name
    // with spaces and capitals is what it refuses.
    audit.lab.h.fake.info = {"Not A Connector The Schema Takes", "1"};
    audit.lab.write_jobs(json::array({job("audit-g")}));

    audit.lab.run_loop(2);

    const std::string log = audit.log_text();
    REQUIRE(has(log, "[audit-g] status error result_invalid: "));
    REQUIRE(has(log, "sent audit-g"));
    const json result = result_in(audit.lab.sent("audit-g"));
    REQUIRE(result.at("status").at("error_code") == "result_invalid");
    audit.finish();
}

TEST_CASE("secret audit J1: one job to the outbox and the Cloud, the same job skipped, the "
          "heartbeat, the record at each of its writes",
          "[secret_audit]")
{
    ServiceAudit audit;
    audit.lab.write_jobs(json::array({job("audit-j1")}));
    std::vector<std::string> records;
    audit.lab.h.fake.at_restore = [&] {
        const connector::ConnectorOptions& told = *audit.lab.h.connector_options;
        told.on_session_opened(kSessionA);
        records.push_back(file_bytes(audit.lab.record_file()).value_or(""));
        told.before_restore_request();
        records.push_back(file_bytes(audit.lab.record_file()).value_or(""));
    };

    audit.lab.run_loop(2);

    const std::string log = audit.log_text();
    REQUIRE(has(log, "run audit-j1: ended pass; queued"));
    REQUIRE(has(log, "sent audit-j1"));
    REQUIRE(has(log, "skipped audit-j1: already sent"));
    REQUIRE(records.size() == 2);
    std::size_t n = 0;
    for (const std::string& record : records) {
        REQUIRE_FALSE(record.empty());
        audit.outputs.add("running.json at write " + std::to_string(++n), record);
    }
    audit.finish();
    CHECK(audit.outputs.has_output("temp/box/sent/audit-j1/result.json"));
    CHECK(audit.outputs.has_output("cloud request 1 body")); // the heartbeat
}

TEST_CASE("secret audit J3: a jobs file that isn't JSON", "[secret_audit]")
{
    ServiceAudit audit;
    audit.lab.h.dir.write("jobs.json", "{not json");

    audit.lab.run_loop(1);

    REQUIRE(has(audit.log_text(), "jobs error: "));
    REQUIRE(has(audit.log_text(), ": not JSON"));
    audit.finish();
}

TEST_CASE("secret audit J4: a job that is no job, reported as error job_invalid", "[secret_audit]")
{
    ServiceAudit audit;
    audit.lab.write_jobs(json::array({job("audit-j4", 0, 0, 0)}));

    audit.lab.run_loop(1);

    REQUIRE(has(audit.log_text(), "job audit-j4: not a valid job (sample_mail)"));
    REQUIRE(has(audit.log_text(), "sent audit-j4"));
    audit.finish();
}

TEST_CASE("secret audit J5: a killed run's record after a restore request: the hold waiting for "
          "another session of the account, which names the account",
          "[secret_audit]")
{
    ServiceAudit audit;
    audit.lab.hold.emplace();
    audit.lab.hold->running = {{kSessionB, gl::kNow}};
    rp::RunningRecord record = rp::with_session(audit.lab.started_record("audit-j5"), kSessionA);
    record = rp::with_restore_request(record, gl::kNow);
    REQUIRE(audit.lab.write_record(record));

    audit.lab.run_loop(2);

    const std::string log = audit.log_text();
    REQUIRE(has(log, "interrupted run audit-j5 found: taken "));
    REQUIRE(has(log, "waiting for Veeam: 1 session(s) of " + std::string{audit::kUserName} +
                         " still Working since "));
    REQUIRE(has(log, "sent audit-j5"));
    audit.finish();
    // The account's name is no secret value: it is in the log, and that is
    // all that is said of it (docs/decisions.md 2026-10-09 W4.9 point 2).
    CHECK(audit.outputs.count(audit::kUserName) >= 1);
    CHECK(audit.outputs.count(audit::kVeeamPassword) == 0);
}

TEST_CASE("secret audit J6: the hold over after a restore request: the recovery clean, the record "
          "gone",
          "[secret_audit]")
{
    ServiceAudit audit;
    audit.lab.hold.emplace();
    const rp::RunningRecord record = rp::with_restore_request(
        rp::with_session(audit.lab.started_record("audit-j6"), kSessionA), gl::kNow);
    REQUIRE(audit.lab.write_record(record));

    audit.lab.run_loop(1);

    const std::string log = audit.log_text();
    REQUIRE(has(log, "recovery clean for audit-j6:"));
    REQUIRE(has(log, "[audit-j6] cleanup before ok: "));
    REQUIRE_FALSE(std::filesystem::exists(audit.lab.record_file()));
    audit.finish();
}

TEST_CASE("secret audit J7: a close that fails because the vault can't be read", "[secret_audit]")
{
    ServiceAudit audit;
    audit.lab.h.load_secrets = []() -> rp::Secrets {
        throw rp::ConfigError("vault", "the vault file can't be read");
    };
    REQUIRE(audit.lab.write_record(audit.lab.started_record("audit-j7")));
    std::filesystem::create_directories(audit.lab.runs() / "audit-j7");

    audit.lab.run_loop(1);

    REQUIRE(has(audit.log_text(), "run audit-j7: couldn't be closed (vault)"));
    audit.finish();
}

// --- K: the commands that read the vault ---------------------------------------------------

TEST_CASE("secret audit K: config check, vault list|test|set|remove, signer public-key and new-key, graph certificate and veeam "
          "list --record on a DPAPI vault of the sentinels",
          "[secret_audit]")
{
    AuditLab lab;
    const std::filesystem::path vault_path = lab.dir.path() / "vault.bin";
    rp::write_vault(vault_path, audit::secrets());
    const std::string vault = utf8(vault_path);
    const std::string config = utf8(lab.config_path);
    const auto cli = [&](const Args& args) {
        std::ostringstream out;
        std::ostringstream err;
        const int code = rp::run_cli(args, out, err);
        return Run{code, out.str(), err.str()};
    };

    const Run check = cli({"config", "check", "--config", config, "--vault", vault});
    REQUIRE(check.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(check.out, ContainsSubstring("secrets (vault "));
    REQUIRE_THAT(check.out, ContainsSubstring("**** (set)"));
    lab.collect("config check", check);

    const Run list = cli({"vault", "list", "--vault", vault});
    REQUIRE(list.exit_code == rp::exit_code::ok);
    lab.collect("vault list", list);
    const Run test = cli({"vault", "test", "--vault", vault});
    REQUIRE(test.exit_code == rp::exit_code::ok);
    lab.collect("vault test", test);

    const Run key = cli({"signer", "public-key", "--vault", vault});
    REQUIRE(key.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(key.out, ContainsSubstring("-----BEGIN PUBLIC KEY-----"));
    REQUIRE_THAT(key.err, ContainsSubstring("key "));
    lab.collect("signer public-key", key);

    // W7.1: signer new-key --replace into the sentinel vault, on a seed of the
    // test's own (RFC 8032 test 1's: the audit's key is test 2's), whose three
    // shapes join the search; the real environment writes the vault.
    lab.searched.add_base64("new signing key", std::string{rp::test::kSigningKey1Base64});
    lab.searched.add("new signing seed (base64)",
                     rp::base64_encode(rp::test::bytes_from_hex(rp::test::kSigningSeed1Hex)));
    lab.searched.add("new signing seed (hex)", std::string{rp::test::kSigningSeed1Hex});
    rp::SignerCommandEnv signer_env = rp::default_signer_command_env();
    signer_env.random_seed = [](std::span<unsigned char, rp::kEd25519SeedBytes> seed) {
        const std::vector<unsigned char> bytes = rp::test::bytes_from_hex(rp::test::kSigningSeed1Hex);
        std::copy(bytes.begin(), bytes.end(), seed.begin());
        return true;
    };
    {
        std::ostringstream new_out;
        std::ostringstream new_err;
        const Args new_key_args{"new-key", "--vault", vault, "--replace"};
        const int new_code = rp::run_signer_command(new_key_args, new_out, new_err, signer_env);
        const Run new_key{new_code, new_out.str(), new_err.str()};
        REQUIRE(new_key.exit_code == rp::exit_code::ok);
        REQUIRE_THAT(new_key.out, ContainsSubstring("-----BEGIN PUBLIC KEY-----"));
        REQUIRE_THAT(new_key.err, ContainsSubstring("set signing_key_base64 in "));
        lab.collect("signer new-key --replace", new_key);
    }

    // W7.0: the Graph certificate's public half; the PFX, its password and the key stay in.
    const Run certificate = cli({"graph", "certificate", "--vault", vault});
    REQUIRE(certificate.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(certificate.out, ContainsSubstring("-----BEGIN CERTIFICATE-----"));
    REQUIRE_THAT(certificate.err, ContainsSubstring("thumbprint "));
    lab.collect("graph certificate", certificate);

    // vault set and remove, the value handed in through the Env.
    const std::string new_password = "Sentinel-Audit-Veeam-Password-2d7f-replaced";
    lab.searched.add("vault set value", new_password);
    rp::VaultCommandEnv vault_env;
    vault_env.default_vault_path = [&] { return vault_path; };
    vault_env.read_secret = [&](std::string_view) {
        return rp::SecretValue{rp::SecretValue::State::ok, new_password};
    };
    const auto vault_command = [&](const Args& args) {
        std::ostringstream out;
        std::ostringstream err;
        const int code = rp::run_vault_command(args, out, err, vault_env);
        return Run{code, out.str(), err.str()};
    };
    const Run set = vault_command({"set", "veeam_password", "--vault", vault});
    REQUIRE(set.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(set.out, ContainsSubstring("set veeam_password in "));
    lab.collect("vault set", set);
    const Run removed = vault_command({"remove", "veeam_password", "--vault", vault});
    REQUIRE(removed.exit_code == rp::exit_code::ok);
    lab.collect("vault remove", removed);

    // veeam list --record on the recorded organisation and restore points.
    rp::test::FakeHttpClient veeam;
    veeam.on(rp::HttpMethod::post, vrl::kBase + "/v8/token", {audit::veeam_token_response()});
    veeam.on(rp::HttpMethod::get, vrl::kBase + "/v8/Organizations?limit=1000&offset=0",
             {rp::test::load_fixture("veeam", "organizations-200")});
    veeam.on(rp::HttpMethod::get,
             vrl::kBase + "/v8/RestorePoints?organizationId=" + vrl::kOrgId + "&limit=1000&offset=0",
             {rp::test::load_fixture("veeam", "restore-points-200")});
    veeam.on(rp::HttpMethod::post, vrl::kBase + "/v8/token/logout",
             {rp::test::load_fixture("veeam", "logout-204")});
    rp::VeeamCommandEnv veeam_env;
    veeam_env.default_config_path = [&] { return lab.config_path; };
    veeam_env.default_vault_path = [&] { return vault_path; };
    veeam_env.load_secrets = [](const std::filesystem::path&) { return audit::secrets(); };
    veeam_env.make_http = [&](const rp::HttpClientOptions&) -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(veeam);
    };
    veeam_env.client_options.logger = lab.logger;
    veeam_env.client_options.sleep = [](std::chrono::milliseconds) {};
    veeam_env.client_options.jitter = [] { return 0.0; };
    const std::string record = utf8(lab.dir.path() / "rec-veeam");
    std::ostringstream out;
    std::ostringstream err;
    const Args veeam_args{"list", "--config", config, "--record", record};
    const int code = rp::run_veeam_command(veeam_args, out, err, veeam_env);
    const Run veeam_list{code, out.str(), err.str()};
    REQUIRE(veeam_list.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(veeam_list.out, ContainsSubstring("recorded "));
    lab.collect("veeam list --record", veeam_list);

    lab.finish();
    // The vault file was searched too: DPAPI's blob holds no plaintext.
    CHECK(lab.outputs.has_output("temp/vault.bin"));
    CHECK(lab.outputs.has_output("temp/rec-veeam/veeam/"));
}

// --- W4.11: the client check's refusal, and a job of a connector this Worker lacks ------------

TEST_CASE("secret audit L: test --evidence --outbox on a profile whose tenant isn't the "
          "organisation's: error client_mismatch, signed and queued",
          "[secret_audit]")
{
    AuditLab lab;
    lab.command = rp::run_test_command;
    lab.fake.facts = connector::ClientFacts{kOrgName, "11111111-2222-3333-4444-555555555555",
                                            "Office365", "Worldwide"};
    Args args = with_run_id("audit-l");
    args.insert(args.end(), {"--evidence", lab.evidence_arg, "--outbox", lab.outbox_arg});

    const Run run = lab.run(args);

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::service);
    REQUIRE_THAT(run.out, ContainsSubstring("\nstatus error client_mismatch: "));
    REQUIRE_THAT(run.err, ContainsSubstring("client error: client mismatch: "));
    REQUIRE_THAT(run.out, ContainsSubstring("\nsigned "));
    REQUIRE_THAT(run.out, ContainsSubstring("\nqueued "));
    lab.collect("test --evidence --outbox, client_mismatch", run);
    lab.finish();
    CHECK(lab.outputs.has_output("temp/box/outbox/audit-l/result.json"));
}

TEST_CASE("secret audit J8: a job asking for a connector this Worker lacks, reported as error "
          "connector_unknown and sent",
          "[secret_audit]")
{
    ServiceAudit audit;
    audit.lab.write_jobs(json::array({job("audit-j8", 2, 1, 0, "other_backup")}));

    audit.lab.run_loop(1);

    REQUIRE(has(audit.log_text(),
                "job audit-j8: connector type other_backup isn't one this Worker has"));
    REQUIRE(has(audit.log_text(), "sent audit-j8"));
    audit.finish();
    CHECK(audit.outputs.has_output("temp/box/sent/audit-j8/result.json"));
}

// W5.1 (docs/decisions.md 2026-10-15, point 10): the job comes from the Cloud's
// poll and is kept in state\jobs.json; the poll carries the API token in its
// Authorization header alone.
TEST_CASE("secret audit J8: a job of the Cloud's poll, kept, run, sent", "[secret_audit]")
{
    ServiceAudit audit;
    audit.lab.context->config.jobs_file.reset();
    const json document{{"format", "restoreproof.jobs.v1"}, {"jobs", json::array({job("audit-j8")})}};
    audit.lab.cloud.on(rp::HttpMethod::get, "https://cloud.example.invalid/v1/jobs",
                       {rp::test::cloud_answer(200, document.dump())});

    audit.lab.run_loop(2);

    const std::string log = audit.log_text();
    REQUIRE(has(log, "run audit-j8: ended pass; queued"));
    REQUIRE(has(log, "sent audit-j8"));
    audit.finish();
    CHECK(audit.outputs.has_output("temp/state/jobs.json"));
}

// --- W5.1: the registration, the one path that receives a new API token ---------------

TEST_CASE("secret audit M: cloud register --record, a 201 stored; service start's first start; a "
          "409 and a vault that can't be written after the 201",
          "[secret_audit]")
{
    // The W5.1 code review's finding 9: the issued token was searched for
    // and never produced.
    AuditLab lab;
    const std::filesystem::path vault_path = lab.dir.path() / "vault.bin";
    const auto fresh_vault = [&] {
        rp::Secrets held = audit::secrets();
        held.cloud_api_token.reset();
        rp::write_vault(vault_path, held);
    };
    const std::optional<rp::SigningKey> key = rp::SigningKey::from_base64(audit::signing_key_base64());
    REQUIRE(key);
    const nlohmann::json answer{{"worker_id", "65fddc39-0792-4178-8361-49d53450b29e"},
                                {"key_id", key->key_id()},
                                {"api_token", std::string{audit::kIssuedApiToken}}};
    rp::test::FakeHttpClient cloud;
    const std::string url = "https://cloud.example.invalid/v1/workers/register";
    cloud.on(rp::HttpMethod::post, url,
             {rp::test::cloud_answer(201, answer.dump()), rp::test::cloud_answer(201, answer.dump()),
              rp::test::cloud_answer(409, R"({"detail":"key_id: already registered"})"),
              rp::test::cloud_answer(201, answer.dump())});
    rp::CloudCommandEnv env;
    env.make_cloud_http = [&](const rp::Config&) -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(cloud);
    };
    env.default_state_dir = [&] { return lab.dir.path() / "state"; };
    env.host_name = [] { return std::optional<std::string>{"AUDIT-HOST"}; };
    const std::string config = utf8(lab.config_path);
    const std::string vault = utf8(vault_path);
    const std::string record = utf8(lab.dir.path() / "rec-cloud");
    const auto cli = [&](const Args& args, const rp::CloudCommandEnv& with) {
        std::ostringstream out;
        std::ostringstream err;
        const int code = rp::run_cloud_command(args, out, err, with);
        return Run{code, out.str(), err.str()};
    };

    fresh_vault();
    const Run registered =
        cli({"register", "--config", config, "--vault", vault, "--record", record}, env);
    REQUIRE(registered.exit_code == rp::exit_code::ok);
    REQUIRE_THAT(registered.out, ContainsSubstring("registered worker "));
    REQUIRE_THAT(registered.out, ContainsSubstring("recorded 1 exchange(s)"));
    REQUIRE(rp::read_vault(vault_path).cloud_api_token == std::string{audit::kIssuedApiToken});
    lab.collect("cloud register --record", registered);

    fresh_vault();
    std::ostringstream first_out;
    std::ostringstream first_err;
    const int first = rp::first_start(lab.config_path, vault_path, first_out, first_err, env);
    REQUIRE(first == rp::exit_code::ok);
    lab.collect("first start", Run{first, first_out.str(), first_err.str()});

    fresh_vault();
    const Run refused = cli({"register", "--config", config, "--vault", vault}, env);
    REQUIRE(refused.exit_code == rp::exit_code::service);
    lab.collect("cloud register 409", refused);

    // The vault is written back unchanged before the request (point 2), and
    // fails on the write after the 201.
    rp::CloudCommandEnv unwritable = env;
    int writes = 0;
    unwritable.write_secrets = [&writes](const std::filesystem::path& file, const rp::Secrets& next) {
        if (++writes == 2) {
            throw rp::VaultError(utf8(file) + ": the vault file couldn't be written");
        }
        rp::write_vault(file, next);
    };
    const Run unstored = cli({"register", "--config", config, "--vault", vault}, unwritable);
    REQUIRE(unstored.exit_code == rp::exit_code::config);
    REQUIRE_THAT(unstored.err, ContainsSubstring("the API token couldn't be stored"));
    lab.collect("cloud register, the vault unwritable", unstored);

    // A registration's body carries the install token, the one secret the
    // Cloud is sent there: it is checked and taken out before the search.
    std::size_t n = 0;
    for (const rp::HttpRequest& request : cloud.requests()) {
        const std::string prefix = "cloud request " + std::to_string(++n);
        lab.outputs.add(prefix + " url", request.url);
        for (const auto& [name, value] : request.headers) {
            lab.outputs.add(prefix + " header " + name, value);
        }
        std::string body = request.body;
        const std::size_t at = body.find(audit::kInstallToken);
        REQUIRE(at != std::string::npos);
        body.erase(at, audit::kInstallToken.size());
        CHECK(body.find(audit::kInstallToken) == std::string::npos);
        lab.outputs.add(prefix + " body", body);
    }
    CHECK(n == 4);

    // The vault itself is DPAPI's blob; the rest of the temp folder (state    // worker.json, the recording) is searched by finish().
    lab.finish();
    CHECK(lab.outputs.has_output("temp/state/worker.json"));
    CHECK(lab.outputs.has_output("temp/rec-cloud/"));
}
