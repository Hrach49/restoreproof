// W2.8 (#33): `rpworker restore` (rp::run_restore_command). The command's own
// logic runs over a fake IConnector: its arguments, the manifest, the restore
// point, the sample, the output and the exit codes. A few runs go through the
// real veeam_m365 connector from the default registry on W2.4's recorded
// answers (FakeHttpClient): Veeam unreachable, a guard refusal, and a whole
// restore. No network, and nothing live. The choices are the 2026-09-30 W2.8
// entry in docs/decisions.md.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "target_guard_lab.hpp"
#include "test_support.hpp"
#include "veeam_restore_lab.hpp"

#include <rp/canary_manifest.hpp>
#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/http_client.hpp>
#include <rp/restore_command.hpp>
#include <rp/sample_rng.hpp>
#include <rp/secrets.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <ostream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;
using Args = std::vector<std::string_view>;
using namespace std::chrono_literals;

namespace {

namespace connector = rp::connector;
namespace sampling = rp::sampling;
using nlohmann::json;
using rp::test::graph_lab::kClient;
using rp::test::graph_lab::kTenant;
using rp::test::graph_lab::lab_values;

const std::string kUsage =
    "usage: rpworker --version | rpworker config check [--config <path>] | "
    "rpworker veeam list [--config <path>] | rpworker graph list [--hash] [--config <path>] | "
    "rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] "
    "[--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>]\n";

const std::string kOrgName = "RestoreProofLab.onmicrosoft.com";
// Veeam's restore point IDs are two GUIDs run together. Made up.
const std::string kNewestId =
    "c2f0f2e7-177f-48ac-992b-93a50cf702e3" "5e1c0a24-0000-4000-8000-000000000930";
const std::string kOlderId =
    "c2f0f2e7-177f-48ac-992b-93a50cf702e3" "5e1c0a24-0000-4000-8000-000000000929";
const std::string kNewestTime = "2026-09-29T22:00:45.6603083Z";
const std::string kOlderTime = "2026-09-28T22:00:40Z";
const std::string kRunId = "run-0001";
const std::string kGeneratedRunId = "rp-20260930T100000Z-0123abcd";
const std::string kCarol = "carol@RestoreProofLab.onmicrosoft.com";

std::string seed_of(const std::string& run_id)
{
    return sampling::seed_hex(sampling::seed_from_run_id(run_id));
}

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

std::string lab_manifest_text()
{
    const std::filesystem::path path =
        std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "seed-manifest.json";
    std::ifstream file(path, std::ios::binary);
    REQUIRE(file);
    return {std::istreambuf_iterator<char>(file), {}};
}

// The lab manifest with only the first `mail`, `sp` and `od` entries of each kind.
std::string trimmed_manifest(std::size_t mail, std::size_t sp, std::size_t od)
{
    json manifest = json::parse(lab_manifest_text());
    json kept = json::array();
    std::size_t m = 0;
    std::size_t s = 0;
    std::size_t o = 0;
    for (const json& entry : manifest.at("entries")) {
        const std::string kind = entry.at("kind").get<std::string>();
        if ((kind == "mail" && m++ < mail) || (kind == "sharepoint_file" && s++ < sp) ||
            (kind == "onedrive_file" && o++ < od)) {
            kept.push_back(entry);
        }
    }
    manifest["entries"] = kept;
    return manifest.dump(2);
}

// The lab's restore targets and tenant, Veeam at the recorded runs' URL.
json config_values()
{
    const rp::test::graph_lab::Lab_values& v = lab_values();
    return {
        {"cloud_url", "https://cloud.example.invalid"},
        {"veeam_url", rp::test::veeam_restore_lab::kBase},
        {"veeam_org_name", kOrgName},
        {"graph_tenant_id", kTenant},
        {"graph_client_id", kClient},
        {"test_mailbox", v.mailbox},
        {"test_site_id", v.site_id},
        {"test_library_id", v.library_id},
        {"test_onedrive_drive_id", v.onedrive_drive_id},
        {"test_onedrive_folder_id", v.folder_id},
    };
}

connector::RestorePoint point(const std::string& id, const std::string& time)
{
    connector::RestorePoint p;
    p.id = id;
    p.backup_time = time;
    p.has_mail = p.has_sharepoint = p.has_onedrive = true;
    return p;
}

struct SessionTimes {
    std::string started;
    std::string ended;
};

// A restore that went as planned: one session per type with items, each item
// restored.
connector::RestoreResult restored(const connector::RestoreSpec& spec)
{
    connector::RestoreResult result;
    result.status = spec.item_count() == 0 ? connector::RestoreStatus::not_run
                                           : connector::RestoreStatus::succeeded;
    const auto add = [&](connector::ItemKind kind, const std::vector<std::string>& names,
                         const SessionTimes& times) {
        if (names.empty()) {
            return;
        }
        const std::string id = "sess-" + std::string{connector::to_string(kind)};
        const int n = static_cast<int>(names.size());
        result.session_ids.push_back(id);
        result.sessions.push_back({id, kind, "Success", "", times.started, times.ended, n, n});
        for (const std::string& name : names) {
            result.items.push_back({kind, name, id, connector::ItemOutcome::restored, "", false});
        }
        result.items_sent += n;
        result.items_restored += n;
    };
    std::vector<std::string> mail;
    for (const connector::MailSelector& m : spec.mail) {
        mail.push_back(m.subject);
    }
    std::vector<std::string> sp;
    for (const connector::SharePointSelector& s : spec.sharepoint) {
        sp.push_back(s.name);
    }
    std::vector<std::string> od;
    for (const connector::OneDriveSelector& o : spec.onedrive) {
        od.push_back(o.name);
    }
    add(connector::ItemKind::mail, mail, {"2026-09-30T10:00:00Z", "2026-09-30T10:01:05Z"});
    add(connector::ItemKind::sharepoint, sp, {"2026-09-30T10:01:10Z", "2026-09-30T10:01:52.25Z"});
    add(connector::ItemKind::onedrive, od, {"2026-09-30T10:02:00Z", "2026-09-30T10:04:00.5Z"});
    return result;
}

// A connector that answers from what the test set. Called on the test's thread.
struct FakeConnector {
    std::vector<connector::RestorePoint> points{point(kNewestId, kNewestTime),
                                                point(kOlderId, kOlderTime)};
    connector::CandidatePool pool;
    std::function<void()> points_throw;
    std::function<void()> candidates_throw;
    std::function<void()> restore_throw;
    // Called first in restore_sample, on the test's thread.
    std::function<void()> at_restore;
    std::function<connector::RestoreResult(const connector::RestoreSpec&)> answer = restored;
    // What the command's stdout held when restore_sample was called.
    const std::ostringstream* out = nullptr;
    std::shared_ptr<spdlog::logger> logger;

    int points_calls = 0;
    int candidate_calls = 0;
    int restore_calls = 0;
    std::string client_ref;
    std::string out_at_restore;
    std::optional<connector::RestoreSpec> spec;
};

class ForwardingConnector final : public connector::IConnector {
public:
    explicit ForwardingConnector(FakeConnector& fake) : fake_(fake) {}

    connector::ConnectorInfo describe() const override { return {"fake", "1"}; }

    std::vector<connector::RestorePoint> list_restore_points(const std::string& client_ref) override
    {
        ++fake_.points_calls;
        fake_.client_ref = client_ref;
        if (fake_.points_throw) {
            fake_.points_throw();
        }
        return fake_.points;
    }

    connector::CandidatePool list_candidates(const connector::CandidateQuery&) override
    {
        ++fake_.candidate_calls;
        if (fake_.candidates_throw) {
            fake_.candidates_throw();
        }
        return fake_.pool;
    }

    connector::RestoreResult restore_sample(const connector::RestoreSpec& spec) override
    {
        ++fake_.restore_calls;
        if (fake_.at_restore) {
            fake_.at_restore();
        }
        fake_.out_at_restore = fake_.out ? fake_.out->str() : "";
        fake_.spec = spec;
        // The connector's own log line: never on stdout.
        if (fake_.logger) {
            fake_.logger->warn("fake connector: SENTINEL-LOG-LINE");
        }
        if (fake_.restore_throw) {
            fake_.restore_throw();
        }
        return fake_.answer(spec);
    }

private:
    FakeConnector& fake_;
};

struct Run {
    int exit_code;
    std::string out;
    std::string err;
};

// A temp folder with config.json and the lab's manifest beside it, the fake
// connector, secrets, a clock and a run ID the test chose.
struct Harness {
    explicit Harness(const json& config_edit = json::object())
    {
        json config = config_values();
        config.update(config_edit);
        config_path = dir.write("config.json", config.dump(2));
        manifest_path = dir.write("seed-manifest.json", lab_manifest_text());
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("restore_command_test", sink);
        logger->set_pattern("[%l] %v");
        logger->set_level(spdlog::level::trace);
    }

    rp::RestoreCommandEnv env()
    {
        rp::RestoreCommandEnv env;
        env.default_config_path = [this] {
            ++default_path_calls;
            return config_path;
        };
        env.load_secrets = [this] {
            ++load_secrets_calls;
            return load_secrets();
        };
        env.make_connector = [this](const rp::Config& config, const rp::Secrets&,
                                    const connector::ConnectorOptions& options)
            -> std::unique_ptr<connector::IConnector> {
            ++make_connector_calls;
            made_for_org = config.veeam_org_name;
            fake.logger = options.logger;
            if (connector_throw) {
                connector_throw();
            }
            if (!give_connector) {
                return nullptr;
            }
            return std::make_unique<ForwardingConnector>(fake);
        };
        env.connector_options.logger = logger;
        // The certificate is checked at the time the lab's is valid.
        env.connector_options.wall_now = [] { return rp::test::graph_lab::kNow; };
        env.make_run_id = [this] {
            ++run_id_calls;
            return kGeneratedRunId;
        };
        env.now = [this] {
            const std::chrono::steady_clock::time_point t =
                std::chrono::steady_clock::time_point{} + clock;
            clock += tick;
            return t;
        };
        return env;
    }

    // `args`, then --config <the temp config>.
    Run run(Args args)
    {
        const std::string path_arg = utf8(config_path);
        args.push_back("--config");
        args.push_back(path_arg);
        return run_raw(args);
    }

    // `args`, then --config, with stdout on `out`: the code and stderr.
    std::pair<int, std::string> run_to(Args args, std::ostream& out)
    {
        const std::string path_arg = utf8(config_path);
        args.push_back("--config");
        args.push_back(path_arg);
        std::ostringstream err;
        const int code = rp::run_restore_command(args, out, err, env());
        return {code, err.str()};
    }

    Run run_raw(const Args& args)
    {
        std::ostringstream out;
        std::ostringstream err;
        fake.out = &out;
        const int code = rp::run_restore_command(args, out, err, env());
        fake.out = nullptr;
        return {code, out.str(), err.str()};
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    rp::test::TempDir dir;
    std::filesystem::path config_path;
    std::filesystem::path manifest_path;
    FakeConnector fake;
    std::function<rp::Secrets()> load_secrets = [] {
        return rp::Secrets{"rp-veeam", "Sentinel-Veeam-Password-9c2e",
                           rp::test::graph_lab::pfx_base64(),
                           std::string{rp::test::graph_lab::kPfxPassword}};
    };
    std::function<void()> connector_throw;
    bool give_connector = true;
    std::chrono::nanoseconds clock{0};
    std::chrono::nanoseconds tick = 123s;
    int default_path_calls = 0;
    int load_secrets_calls = 0;
    int make_connector_calls = 0;
    int run_id_calls = 0;
    std::string made_for_org;
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
};

connector::MailSelector carol_mail(int n)
{
    return {kCarol, "Archive", "real mail 0" + std::to_string(n),
            "2026-09-20T10:00:0" + std::to_string(n) + "Z"};
}

// What `--run-id run-0001` on the newest point prints before the sample is
// chosen.
std::string expected_intro()
{
    return "restore point " + kNewestTime + "  " + kNewestId + "  (veeam_org_name " + kOrgName +
           ")\n"
           "run run-0001  seed " +
           seed_of(kRunId) + "\n";
}

// The header of `--mail 2 --sp 1 --od 0 --run-id run-0001` on the newest point
// with one random mail candidate.
std::string expected_header()
{
    return expected_intro() +
           "canary cursor 0,0,0 -> 1,1,0\n"
           "  KIND        REQUESTED  CANARIES  RANDOM  NOTE\n"
           "  mail        2          1 of 1    1 of 1\n"
           "  sharepoint  1          1 of 1    0 of 0\n"
           "  onedrive    0          0 of 0    0 of 0\n"
           "restoring 3 item(s) ...\n";
}

} // namespace

// --- Failure paths: the command line -----------------------------------------------

TEST_CASE("restore: a command line it doesn't understand is a usage error, before the config",
          "[restore_command]")
{
    const std::string long_id(129, 'a');
    const Args args = GENERATE_COPY(values<Args>({
        {"list"},
        {"--mails", "1"},
        {"--mail"},
        {"--mail", "101"},
        {"--mail", "1000"},
        {"--mail", "0100"},
        {"--mail", "-1"},
        {"--mail", "+1"},
        {"--mail", ""},
        {"--mail", "1 "},
        {"--mail", "\xd9\xa3"}, // ARABIC-INDIC DIGIT THREE
        {"--mail", "1", "--mail", "2"},
        {"--sp", "x"},
        {"--sp", "1", "--sp", "1"},
        {"--od", "200"},
        {"--od", "1", "--od", "1"},
        {"--point", "nope!"},
        {"--point", ""},
        {"--point", "Latest!"},
        {"--point", long_id},
        {"--point", "latest", "--point", "latest"},
        {"--point", "c2f0f2e7-177f-48ac-992b-93a50cf702e3\n"},
        {"--run-id", "bad id"},
        {"--run-id", ""},
        {"--run-id", "a", "--run-id", "a"},
        {"--canary-cursor", "1,2"},
        {"--canary-cursor", "1,2,3,4"},
        {"--canary-cursor", "1, 2,3"},
        {"--canary-cursor", "-1,0,0"},
        {"--canary-cursor", "+1,0,0"},
        {"--canary-cursor", "1234567,0,0"},
        {"--canary-cursor", "0,0,4294967296"},
        {"--canary-cursor", "1,,2"},
        {"--canary-cursor", ",1,2"},
        {"--canary-cursor", "1,2,"},
        {"--canary-cursor", "a,b,c"},
        {"--canary-cursor", ""},
        {"--canary-cursor", "0,0,0", "--canary-cursor", "0,0,0"},
        {"--manifest"},
        {"--manifest", "a.json", "--manifest", "b.json"},
        {"--config"},
        {"--config", "a.json", "--config", "b.json"},
    }));
    CAPTURE(args);
    Harness lab;

    const Run run = lab.run_raw(args);

    CHECK(run.exit_code == rp::exit_code::usage);
    CHECK(run.out.empty());
    CHECK(run.err == kUsage);
    CHECK(lab.default_path_calls == 0);
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: every sample size 0, from the flags or the config, is a usage error",
          "[restore_command]")
{
    const auto [config_edit, args] = GENERATE(table<json, Args>({
        {json::object(), Args{"--mail", "0", "--sp", "0", "--od", "000"}},
        {json{{"sample_mail", 0}, {"sample_sp", 0}, {"sample_od", 1}}, Args{"--od", "0"}},
    }));
    Harness lab(config_edit);

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::usage);
    CHECK(run.out.empty());
    CHECK(run.err == "usage error: every sample size is 0 (--mail, --sp, --od, or config's "
                     "sample_mail, sample_sp, sample_od): nothing to restore\n");
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: a canary cursor out of the manifest's range is a usage error, before the "
          "connector",
          "[restore_command]")
{
    const auto [cursor, message] = GENERATE(table<std::string, std::string>({
        {"20,0,0", "the mail cursor must be below 20, the manifest's mail canaries"},
        {"0,10,0", "the sharepoint cursor must be below 10, the manifest's sharepoint canaries"},
        {"0,0,999999", "the onedrive cursor must be below 10, the manifest's onedrive canaries"},
    }));
    Harness lab;

    const Run run = lab.run({"--canary-cursor", cursor});

    CHECK(run.exit_code == rp::exit_code::usage);
    CHECK(run.out.empty());
    CHECK(run.err == "usage error: --canary-cursor: " + message + "\n");
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: a cursor for a type the manifest has no canaries of must be 0",
          "[restore_command]")
{
    Harness lab;
    lab.dir.write("seed-manifest.json", trimmed_manifest(2, 2, 0));

    const Run run = lab.run({"--canary-cursor", "0,0,1"});

    CHECK(run.exit_code == rp::exit_code::usage);
    CHECK(run.err == "usage error: --canary-cursor: the onedrive cursor must be 0: the manifest "
                     "has no onedrive canaries\n");
    CHECK(lab.make_connector_calls == 0);
}

// --- Failure paths: config, secrets, manifest --------------------------------------

TEST_CASE("restore: a config that doesn't load is a config error", "[restore_command]")
{
    Harness lab;

    const Run run = lab.run_raw({"--config", "no-such-config.json"});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "config error: no-such-config.json: cannot read config file\n");
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: without --config it reads the default config", "[restore_command]")
{
    Harness lab;

    const Run run = lab.run_raw({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(lab.default_path_calls == 1);
}

TEST_CASE("restore: both Veeam secrets and the Graph certificate are needed, before any Veeam "
          "call",
          "[restore_command]")
{
    using Secret = std::optional<std::string>;
    const Secret pfx = rp::test::graph_lab::pfx_base64();
    const Secret pfx_password = std::string{rp::test::graph_lab::kPfxPassword};
    const auto [username, password, pfx_value, password_value, message] =
        GENERATE_COPY(table<Secret, Secret, Secret, Secret, std::string>({
            {std::nullopt, "p", pfx, pfx_password, "config error: RP_VEEAM_USERNAME is not set\n"},
            {std::string{}, "p", pfx, pfx_password, "config error: RP_VEEAM_USERNAME is not set\n"},
            {"u", std::nullopt, pfx, pfx_password, "config error: RP_VEEAM_PASSWORD is not set\n"},
            {"u", std::string{}, pfx, pfx_password, "config error: RP_VEEAM_PASSWORD is not set\n"},
            {"u", "p", std::nullopt, pfx_password,
             "config error: RP_GRAPH_CERT_PFX_BASE64 is not set\n"},
            {"u", "p", std::string{}, std::nullopt,
             "config error: RP_GRAPH_CERT_PFX_BASE64 is not set\n"},
            {"u", "p", pfx, std::nullopt,
             "config error: RP_GRAPH_CERT_PASSWORD is not set, and the PFX in "
             "RP_GRAPH_CERT_PFX_BASE64 needs a password\n"},
            {"u", "p", pfx, std::string{},
             "config error: RP_GRAPH_CERT_PASSWORD is not set, and the PFX in "
             "RP_GRAPH_CERT_PFX_BASE64 needs a password\n"},
        }));
    Harness lab;
    lab.load_secrets = [=] { return rp::Secrets{username, password, pfx_value, password_value}; };

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == message);
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: a Graph certificate that doesn't open or isn't valid is a config error, "
          "before any Veeam call",
          "[restore_command]")
{
    namespace gl = rp::test::graph_lab;
    const auto [what, message] = GENERATE(table<std::string, std::string>({
        {"wrong password",
         "config error: RP_GRAPH_CERT_PASSWORD does not open the PFX in RP_GRAPH_CERT_PFX_BASE64\n"},
        {"not Base64", "config error: RP_GRAPH_CERT_PFX_BASE64"},
        {"expired", "config error: "},
    }));
    CAPTURE(what);
    Harness lab;
    std::string pfx = gl::pfx_base64();
    std::string password = gl::kPfxPassword;
    if (what == "wrong password") {
        password = "Sentinel-Wrong-Password-7e21";
    } else if (what == "not Base64") {
        pfx = "not base64 at all!";
    } else {
        pfx = rp::test::to_base64(rp::test::make_pfx(
            rp::test::make_client_cert(
                "RestoreProof Worker",
                rp::test::ClientCertOptions{.not_before = -7200,
                                            .not_after = -3600,
                                            .now = std::chrono::system_clock::to_time_t(gl::kNow)}),
            gl::kPfxPassword));
    }
    lab.load_secrets = [=] { return rp::Secrets{"u", "p", pfx, password}; };

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    if (what == "wrong password") {
        CHECK(run.err == message);
    } else {
        CHECK_THAT(run.err, StartsWith(message));
    }
    CHECK_THAT(run.err, !ContainsSubstring(password));
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: a PFX without a password needs no RP_GRAPH_CERT_PASSWORD, as graph list",
          "[restore_command]")
{
    namespace gl = rp::test::graph_lab;
    using Secret = std::optional<std::string>;
    const Secret password = GENERATE(Secret{std::nullopt}, Secret{std::string{}});
    Harness lab;
    const std::string pfx = rp::test::to_base64(rp::test::make_pfx(
        rp::test::make_client_cert(
            "RestoreProof Worker",
            rp::test::ClientCertOptions{.now = std::chrono::system_clock::to_time_t(gl::kNow)}),
        ""));
    lab.load_secrets = [=] { return rp::Secrets{"u", "p", pfx, password}; };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK(lab.fake.restore_calls == 1);
}

TEST_CASE("restore: secrets that fail to load are config errors; an unexpected one hides its "
          "message",
          "[restore_command]")
{
    const auto [kind, message] = GENERATE(table<std::string, std::string>({
        {"ConfigError", "config error: environment variable RP_VEEAM_PASSWORD is not valid Unicode\n"},
        {"other", "config error: unexpected failure\n"},
    }));
    Harness lab;
    lab.load_secrets = [kind = kind]() -> rp::Secrets {
        if (kind == "ConfigError") {
            throw rp::ConfigError("RP_VEEAM_PASSWORD",
                                  "environment variable RP_VEEAM_PASSWORD is not valid Unicode");
        }
        throw std::runtime_error("SENTINEL-SECRET-MESSAGE");
    };

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == message);
}

TEST_CASE("restore: a manifest that doesn't load or isn't the tenant's is a config error, "
          "before the connector",
          "[restore_command]")
{
    const auto [what, message] = GENERATE(table<std::string, std::string>({
        {"missing", "cannot read the file"},
        {"not json", "config error: canary manifest: isn't valid JSON\n"},
        {"another tenant",
         "config error: canary manifest: /tenant_id: isn't the client's tenant (graph_tenant_id)\n"},
    }));
    CAPTURE(what);
    Harness lab;
    if (what == "missing") {
        std::filesystem::remove(lab.manifest_path);
    } else if (what == "not json") {
        lab.dir.write("seed-manifest.json", "{not json");
    } else {
        json manifest = json::parse(lab_manifest_text());
        manifest["tenant_id"] = "00000000-0000-4000-8000-000000000001";
        lab.dir.write("seed-manifest.json", manifest.dump());
    }

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    if (what == "missing") {
        CHECK(run.err == "config error: canary manifest: " + utf8(lab.manifest_path) +
                             ": cannot read the file\n");
    } else {
        CHECK(run.err == message);
    }
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: a manifest that names a restore target is a config error, before the "
          "connector",
          "[restore_command]")
{
    Harness lab;
    json manifest = json::parse(lab_manifest_text());
    // Entry 30 is the first OneDrive canary.
    REQUIRE(manifest["entries"][30]["kind"] == "onedrive_file");
    manifest["entries"][30]["location"]["folder_path"] = "/RestoreTarget";
    lab.dir.write("seed-manifest.json", manifest.dump());
    // Veeam unreachable: the manifest must be refused first, never exit 3.
    lab.fake.points_throw = [] { throw connector::TransientError("Veeam unreachable"); };

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "config error: canary manifest: /entries/30/location/folder_path: is in a "
                     "restore target (a RestoreTarget folder)\n");
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: --manifest reads the file it names, not the one beside the config",
          "[restore_command]")
{
    Harness lab;
    std::filesystem::remove(lab.manifest_path);
    rp::test::TempDir other;
    const std::string path = utf8(other.write("pilot-manifest.json", trimmed_manifest(1, 1, 1)));

    const Run run = lab.run({"--manifest", path, "--run-id", kRunId, "--mail", "1", "--sp", "0",
                             "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    REQUIRE(lab.fake.spec);
    CHECK(lab.fake.spec->mail.size() == 1);
}

TEST_CASE("restore: a --manifest path that isn't UTF-8 is a config error", "[restore_command]")
{
    Harness lab;

    const Run run = lab.run({"--manifest", "\xff.json"});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "config error: the --manifest path is not valid UTF-8\n");
    CHECK(lab.make_connector_calls == 0);
}

// --- Failure paths: the connector --------------------------------------------------

TEST_CASE("restore: each failure of the restore has its exit code; the header is already out, "
          "and items may be in the targets",
          "[restore_command]")
{
    // restore_sample may have sent a restore before it threw.
    const std::string started =
        "restore error: the restore had started: items may be in the restore targets (run "
        "run-0001)\n";
    struct Case {
        std::string name;
        std::function<void()> raise;
        int code;
        std::string err;
    };
    const std::vector<Case> cases{
        {"AuthError", [] { throw connector::AuthError("Veeam refused the credentials"); },
         rp::exit_code::auth, "restore error: Veeam refused the credentials\n" + started},
        {"TransientError", [] { throw connector::TransientError("Veeam unreachable"); },
         rp::exit_code::transient, "restore error: Veeam unreachable\n" + started},
        {"SafetyViolation",
         [] {
             throw connector::SafetyViolation(
                 "target guard: mail item 0 is sampled from a restore target");
         },
         rp::exit_code::service,
         "restore error: target guard: mail item 0 is sampled from a restore target\n" + started},
        {"NotFoundError", [] { throw connector::NotFoundError("mail item 0 isn't in the restore point"); },
         rp::exit_code::service, "restore error: mail item 0 isn't in the restore point\n" + started},
        {"NotImplementedError", [] { throw connector::NotImplementedError("not here"); },
         rp::exit_code::service, "restore error: not here\n" + started},
        // The connector's promise that no restore was sent: no note.
        {"nothing restored",
         [] {
             throw connector::SafetyViolation(
                 "target guard: mail item 0 is sampled from a restore target; nothing was "
                 "restored");
         },
         rp::exit_code::service,
         "restore error: target guard: mail item 0 is sampled from a restore target; nothing "
         "was restored\n"},
        {"Error", [] { throw connector::Error("Veeam said no"); }, rp::exit_code::service,
         "restore error: Veeam said no\n" + started},
        {"ConfigError",
         [] {
             throw rp::ConfigError("RP_GRAPH_CERT_PFX_BASE64",
                                   "RP_GRAPH_CERT_PFX_BASE64 is not valid Base64");
         },
         rp::exit_code::config, "config error: RP_GRAPH_CERT_PFX_BASE64 is not valid Base64\n"},
        {"unexpected", [] { throw std::runtime_error("SENTINEL-UNSAFE-MESSAGE"); },
         rp::exit_code::config, "error: unexpected failure\n" + started},
    };
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{9}))];
    CAPTURE(c.name);
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.fake.restore_throw = c.raise;

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == c.code);
    CHECK(run.err == c.err);
    CHECK(run.out == expected_header());
    CHECK(lab.fake.restore_calls == 1);
}

TEST_CASE("restore: a failure choosing the sample restores nothing; the run ID is already out",
          "[restore_command]")
{
    struct Case {
        std::string name;
        std::function<void()> raise;
        int code;
        std::string err;
    };
    const std::vector<Case> cases{
        {"TransientError", [] { throw connector::TransientError("Veeam unreachable"); },
         rp::exit_code::transient, "restore error: Veeam unreachable\n"},
        {"AuthError", [] { throw connector::AuthError("Veeam refused the token"); },
         rp::exit_code::auth, "restore error: Veeam refused the token\n"},
        {"Error", [] { throw connector::Error("veeam_m365: an unexpected answer"); },
         rp::exit_code::service, "restore error: veeam_m365: an unexpected answer\n"},
        {"ManifestError",
         [] { throw sampling::ManifestError("canary manifest: /entries/3: a canary in a target"); },
         rp::exit_code::config, "config error: canary manifest: /entries/3: a canary in a target\n"},
    };
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{4}))];
    CAPTURE(c.name);
    Harness lab;
    lab.fake.candidates_throw = c.raise;

    // --mail 2: a random half, so choose_sample lists candidates.
    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == c.code);
    CHECK(run.err == c.err);
    CHECK(run.out == expected_intro());
    CHECK(lab.fake.candidate_calls == 1);
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: a failure listing the restore points restores nothing and prints nothing",
          "[restore_command]")
{
    const auto [kind, code] = GENERATE(table<std::string, int>({
        {"NotFoundError", rp::exit_code::service},
        {"TransientError", rp::exit_code::transient},
        {"AuthError", rp::exit_code::auth},
    }));
    Harness lab;
    lab.fake.points_throw = [kind = kind] {
        if (kind == "NotFoundError") {
            throw connector::NotFoundError("no organisation RestoreProofLab.onmicrosoft.com");
        }
        if (kind == "TransientError") {
            throw connector::TransientError("Veeam unreachable");
        }
        throw connector::AuthError("refused");
    };

    const Run run = lab.run({});

    CHECK(run.exit_code == code);
    CHECK(run.out.empty());
    CHECK_THAT(run.err, StartsWith("restore error: "));
    CHECK(lab.fake.restore_calls == 0);
    CHECK(lab.fake.client_ref == kOrgName);
}

TEST_CASE("restore: a connector the registry doesn't know, or none, fails before any call",
          "[restore_command]")
{
    Harness lab;
    SECTION("unknown")
    {
        lab.connector_throw = [] {
            throw connector::UnknownConnectorError("nope", {"veeam_m365"});
        };
        const Run run = lab.run({});
        CHECK(run.exit_code == rp::exit_code::config);
        CHECK(run.err == "config error: unknown connector \"nope\" (known: veeam_m365)\n");
    }
    SECTION("none")
    {
        lab.give_connector = false;
        const Run run = lab.run({});
        CHECK(run.exit_code == rp::exit_code::config);
        CHECK(run.err == "error: unexpected failure\n");
    }
    CHECK(lab.fake.points_calls == 0);
}

TEST_CASE("restore: an organisation without restore points is a service error",
          "[restore_command]")
{
    Harness lab;
    lab.fake.points.clear();

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.out.empty());
    CHECK(run.err == "restore error: no restore points for veeam_org_name\n");
    CHECK(lab.fake.candidate_calls == 0);
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: a restore point ID that isn't the organisation's is a service error",
          "[restore_command]")
{
    Harness lab;
    const std::string id = "c2f0f2e7-177f-48ac-992b-93a50cf702e3" "5e1c0a24-0000-4000-8000-000000000999";

    const Run run = lab.run({"--point", id});

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.out.empty());
    CHECK(run.err == "restore error: restore point " + id + " not found for veeam_org_name\n");
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: a run ID from the generator that check_run_id refuses restores nothing",
          "[restore_command]")
{
    Harness lab;
    rp::RestoreCommandEnv env = lab.env();
    env.make_run_id = [] { return std::string{"not a run id"}; };
    std::ostringstream out;
    std::ostringstream err;
    const std::string path_arg = utf8(lab.config_path);

    const int code = rp::run_restore_command(Args{"--config", path_arg}, out, err, env);

    CHECK(code == rp::exit_code::config);
    CHECK(err.str() == "error: unexpected failure\n");
    CHECK(out.str().empty());
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: a stdout that takes nothing stops the command before the restore",
          "[restore_command]")
{
    Harness lab;
    rp::test::FailingStreamBuf failing;
    std::ostream out(&failing);
    std::ostringstream err;
    const std::string path_arg = utf8(lab.config_path);

    const int code = rp::run_restore_command(Args{"--config", path_arg}, out, err, lab.env());

    CHECK(code == rp::exit_code::config);
    CHECK(err.str() == "error: unexpected failure\n");
    CHECK(lab.fake.candidate_calls == 0);
    CHECK(lab.fake.restore_calls == 0);
}

namespace {

// A stdout that takes `limit` bytes, then fails, and keeps what it held at
// each sync() (a flush).
class RecordingStreamBuf : public std::streambuf {
public:
    explicit RecordingStreamBuf(std::size_t limit = std::string::npos) : limit_(limit) {}

    std::string text;
    std::vector<std::string> synced;

protected:
    int_type overflow(int_type c) override
    {
        if (traits_type::eq_int_type(c, traits_type::eof())) {
            return traits_type::not_eof(c);
        }
        if (text.size() >= limit_) {
            return traits_type::eof();
        }
        text.push_back(traits_type::to_char_type(c));
        return c;
    }

    std::streamsize xsputn(const char* s, std::streamsize n) override
    {
        const std::size_t room = text.size() >= limit_ ? 0 : limit_ - text.size();
        const std::size_t take = std::min(room, static_cast<std::size_t>(n));
        text.append(s, take);
        return static_cast<std::streamsize>(take);
    }

    int sync() override
    {
        synced.push_back(text);
        return 0;
    }

private:
    std::size_t limit_;
};

} // namespace

TEST_CASE("restore: the run ID is flushed before the sample is chosen, the header before the "
          "restore",
          "[restore_command]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    RecordingStreamBuf buffer;
    std::ostream out(&buffer);
    std::vector<std::string> synced_at_candidates;
    std::vector<std::string> synced_at_restore;
    lab.fake.candidates_throw = [&] { synced_at_candidates = buffer.synced; };
    lab.fake.at_restore = [&] { synced_at_restore = buffer.synced; };

    const auto [code, err] =
        lab.run_to({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"}, out);

    CHECK(code == rp::exit_code::ok);
    CHECK(err.empty());
    CHECK(synced_at_candidates == std::vector<std::string>{expected_intro()});
    CHECK(synced_at_restore == std::vector<std::string>{expected_intro(), expected_header()});
    CHECK(lab.fake.restore_calls == 1);
}

TEST_CASE("restore: a stdout that fails after the restore ran says so, with the run ID and the "
          "restore's status and exit code",
          "[restore_command]")
{
    const auto [status, infrastructure, code, err] =
        GENERATE(table<connector::RestoreStatus, bool, int, std::string>({
            // A restore that succeeded but whose output was lost isn't a success.
            {connector::RestoreStatus::succeeded, false, rp::exit_code::config,
             "error: writing the output failed after the restore ran (run run-0001, status "
             "succeeded: 3 of 3 item(s) restored)\n"},
            {connector::RestoreStatus::partial, false, rp::exit_code::restore,
             "error: writing the output failed after the restore ran (run run-0001, status "
             "partial: 3 of 3 item(s) restored)\n"},
            {connector::RestoreStatus::partial, true, rp::exit_code::service,
             "error: writing the output failed after the restore ran (run run-0001, status "
             "partial: 3 of 3 item(s) restored)\n"
             "restore error: 1 item(s) failed for an infrastructure reason (Veeam couldn't "
             "reach Microsoft 365, lacked permissions or was throttled); this is an error, not "
             "a restore failure\n"},
        }));
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.fake.answer = [status = status, infrastructure = infrastructure](
                          const connector::RestoreSpec& spec) {
        connector::RestoreResult result = restored(spec);
        result.status = status;
        if (infrastructure) {
            result.items.back().outcome = connector::ItemOutcome::failed;
            result.items.back().infrastructure = true;
        }
        return result;
    };
    // The header fits; the tables don't.
    RecordingStreamBuf buffer(expected_header().size() + 5);
    std::ostream out(&buffer);

    const auto [exit_code, error] =
        lab.run_to({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"}, out);

    CHECK(exit_code == code);
    CHECK(error == err);
    CHECK(lab.fake.restore_calls == 1);
    CHECK_THAT(buffer.text, StartsWith(expected_header()));
}

TEST_CASE("restore: a stdout that fails on the run ID stops the command before the sample",
          "[restore_command]")
{
    Harness lab;
    RecordingStreamBuf buffer(10);
    std::ostream out(&buffer);

    const auto [code, err] = lab.run_to({"--run-id", kRunId, "--mail", "2"}, out);

    CHECK(code == rp::exit_code::config);
    CHECK(err == "error: unexpected failure\n");
    CHECK(lab.fake.candidate_calls == 0);
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: a stdout that fails on the sample's table stops the command before the "
          "restore",
          "[restore_command]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    RecordingStreamBuf buffer(expected_intro().size() + 5);
    std::ostream out(&buffer);

    const auto [code, err] =
        lab.run_to({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"}, out);

    CHECK(code == rp::exit_code::config);
    CHECK(err == "error: unexpected failure\n");
    CHECK(lab.fake.candidate_calls == 1);
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: an empty sample restores nothing and is exit 4, the shortfall named",
          "[restore_command]")
{
    const auto [manifest, sizes, cursor_line, reason] =
        GENERATE(table<std::string, Args, std::string, std::string>({
            {trimmed_manifest(0, 1, 0), Args{"--mail", "2", "--sp", "0", "--od", "1"},
             "canary cursor 0,0,0 -> 0,0,0\n",
             "mail: canary and random shortfall; onedrive: canary shortfall"},
            {trimmed_manifest(0, 1, 1), Args{"--mail", "1", "--sp", "0", "--od", "0"},
             "canary cursor 0,0,0 -> 0,0,0\n", "mail: canary shortfall"},
        }));
    Harness lab;
    lab.dir.write("seed-manifest.json", manifest);
    Args args = sizes;
    args.insert(args.end(), {"--run-id", kRunId});

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.err == "restore error: the sample is empty: nothing to restore (" + reason + ")\n");
    CHECK_THAT(run.out, StartsWith(expected_intro() + cursor_line));
    CHECK_THAT(run.out, !ContainsSubstring("restoring"));
    CHECK(lab.fake.restore_calls == 0);
}

// --- The restore ---------------------------------------------------------------------

TEST_CASE("restore: a succeeded restore prints the header, both tables and the status, exit 0",
          "[restore_command]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK(run.out ==
          expected_header() +
              "\n"
              "  KIND        SOURCE  NAME              OUTCOME   SESSION          ELAPSED  MESSAGE\n"
              "  mail        canary  RP-CANARY-0001    restored  sess-mail        0:01:05  -\n"
              "  mail        random  real mail 01      restored  sess-mail        0:01:05  -\n"
              "  sharepoint  canary  rp-canary-01.pdf  restored  sess-sharepoint  0:00:42  -\n"
              "\n"
              "  SESSION          KIND        RESULT   RESTORED  STARTED               ENDED                    ELAPSED\n"
              "  sess-mail        mail        Success  2 of 2    2026-09-30T10:00:00Z  2026-09-30T10:01:05Z     0:01:05\n"
              "  sess-sharepoint  sharepoint  Success  1 of 1    2026-09-30T10:01:10Z  2026-09-30T10:01:52.25Z  0:00:42\n"
              "\n"
              "status succeeded: 3 of 3 item(s) restored in 0:02:03\n");
    // The header went out before the restore began.
    CHECK(lab.fake.out_at_restore == expected_header());
    REQUIRE(lab.fake.spec);
    const connector::RestoreSpec& spec = *lab.fake.spec;
    CHECK(spec.client_ref == kOrgName);
    CHECK(spec.restore_point.id == kNewestId);
    CHECK(spec.restore_point.backup_time == kNewestTime);
    CHECK(spec.targets.mailbox() == lab_values().mailbox);
    CHECK(spec.targets.library_id() == lab_values().library_id);
    REQUIRE(spec.mail.size() == 2);
    CHECK(spec.mail[0].subject == "RP-CANARY-0001");
    CHECK(spec.mail[1].subject == "real mail 01");
    REQUIRE(spec.sharepoint.size() == 1);
    CHECK(spec.onedrive.empty());
    CHECK(lab.run_id_calls == 0);
    CHECK(lab.fake.candidate_calls == 1);
    CHECK(lab.made_for_org == kOrgName);
}

TEST_CASE("restore: a restore that didn't succeed exits 5 with its status line", "[restore_command]")
{
    const auto [status, count] = GENERATE(table<connector::RestoreStatus, int>({
        {connector::RestoreStatus::partial, 1},
        {connector::RestoreStatus::failed, 0},
    }));
    Harness lab;
    lab.fake.answer = [status = status, count = count](const connector::RestoreSpec& spec) {
        connector::RestoreResult result = restored(spec);
        result.status = status;
        result.items_restored = count;
        return result;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::restore);
    CHECK(run.err.empty());
    CHECK_THAT(run.out, ContainsSubstring("\nstatus " + std::string{connector::to_string(status)} +
                                          ": " + std::to_string(count) +
                                          " of 2 item(s) restored in 0:02:03\n"));
}

TEST_CASE("restore: an item failed for an infrastructure reason is exit 4, never 5; the tables "
          "are printed",
          "[restore_command]")
{
    const auto [status, outcomes, infrastructure, code, err] = GENERATE(
        table<connector::RestoreStatus, std::vector<connector::ItemOutcome>, std::vector<bool>,
              int, std::string>({
            {connector::RestoreStatus::partial,
             {connector::ItemOutcome::restored, connector::ItemOutcome::failed},
             {false, true},
             rp::exit_code::service,
             "restore error: 1 item(s) failed for an infrastructure reason (Veeam couldn't "
             "reach Microsoft 365, lacked permissions or was throttled); this is an error, not "
             "a restore failure\n"},
            {connector::RestoreStatus::failed,
             {connector::ItemOutcome::unknown, connector::ItemOutcome::failed},
             {true, true},
             rp::exit_code::service,
             "restore error: 2 item(s) failed for an infrastructure reason (Veeam couldn't "
             "reach Microsoft 365, lacked permissions or was throttled); this is an error, not "
             "a restore failure\n"},
            // One infrastructure failure among restore failures is still an error.
            {connector::RestoreStatus::failed,
             {connector::ItemOutcome::failed, connector::ItemOutcome::failed},
             {false, true},
             rp::exit_code::service,
             "restore error: 1 item(s) failed for an infrastructure reason (Veeam couldn't "
             "reach Microsoft 365, lacked permissions or was throttled); this is an error, not "
             "a restore failure\n"},
            // A restored item's flag counts for nothing.
            {connector::RestoreStatus::partial,
             {connector::ItemOutcome::restored, connector::ItemOutcome::failed},
             {true, false},
             rp::exit_code::restore,
             ""},
        }));
    Harness lab;
    lab.fake.answer = [=](const connector::RestoreSpec& spec) {
        connector::RestoreResult result = restored(spec);
        result.status = status;
        result.items_restored = 0;
        for (std::size_t i = 0; i < result.items.size(); ++i) {
            result.items[i].outcome = outcomes.at(i);
            result.items[i].infrastructure = infrastructure.at(i);
            result.items_restored += outcomes.at(i) == connector::ItemOutcome::restored ? 1 : 0;
        }
        return result;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == code);
    CHECK(run.err == err);
    CHECK_THAT(run.out, ContainsSubstring("\n  KIND        SOURCE  NAME"));
    CHECK_THAT(run.out, ContainsSubstring("\nstatus " + std::string{connector::to_string(status)}));
}

TEST_CASE("restore: a restore that returns not_run is exit 4, never 5", "[restore_command]")
{
    Harness lab;
    lab.fake.answer = [](const connector::RestoreSpec&) { return connector::RestoreResult{}; };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.err == "restore error: the restore did not run: nothing was sent (status not_run)\n");
    // Without items or sessions, only the status line follows the header.
    const std::string last = "restoring 1 item(s) ...\n";
    CHECK(run.out.substr(run.out.find(last) + last.size()) ==
          "\nstatus not_run: 0 of 0 item(s) restored in 0:02:03\n");
}

TEST_CASE("restore: --point latest, or none, is the newest; an ID matches in any case",
          "[restore_command]")
{
    const auto [point_args, expected] = GENERATE(table<Args, std::string>({
        {Args{}, kNewestId},
        {Args{"--point", "latest"}, kNewestId},
        {Args{"--point", "LATEST"}, kNewestId},
        {Args{"--point", "Latest"}, kNewestId},
        {Args{"--point", "C2F0F2E7-177F-48AC-992B-93A50CF702E3" "5E1C0A24-0000-4000-8000-000000000929"},
         kOlderId},
    }));
    Harness lab;
    Args args = point_args;
    args.insert(args.end(), {"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::ok);
    REQUIRE(lab.fake.spec);
    CHECK(lab.fake.spec->restore_point.id == expected);
    CHECK_THAT(run.out, StartsWith("restore point " +
                                   (expected == kNewestId ? kNewestTime : kOlderTime) + "  " +
                                   expected + "  "));
}

TEST_CASE("restore: the edges of the command line are accepted", "[restore_command]")
{
    Harness lab;
    SECTION("--mail 100")
    {
        const Run run = lab.run({"--run-id", kRunId, "--mail", "100", "--sp", "0", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK_THAT(run.out, ContainsSubstring(
                                "  mail        100        20 of 50  0 of 50  canary and random "
                                "shortfall\n"));
    }
    SECTION("a 128-character --point ID passes the command line, and isn't found")
    {
        const std::string id(128, 'a');
        const Run run = lab.run({"--point", id});
        CHECK(run.exit_code == rp::exit_code::service);
        CHECK(run.err == "restore error: restore point " + id + " not found for veeam_org_name\n");
        CHECK(lab.fake.points_calls == 1);
    }
    SECTION("--canary-cursor 0,0,9: the last OneDrive canary")
    {
        const Run run = lab.run(
            {"--run-id", kRunId, "--canary-cursor", "0,0,9", "--mail", "0", "--sp", "0", "--od", "1"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK_THAT(run.out, ContainsSubstring("\ncanary cursor 0,0,9 -> 0,0,0\n"));
        REQUIRE(lab.fake.spec);
        CHECK(lab.fake.spec->onedrive.at(0).name == "rp-canary-20.png");
    }
    SECTION("a cursor of 0 for a type the manifest has no canaries of")
    {
        lab.dir.write("seed-manifest.json", trimmed_manifest(1, 1, 0));
        const Run run = lab.run(
            {"--run-id", kRunId, "--canary-cursor", "0,0,0", "--mail", "1", "--sp", "1", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        REQUIRE(lab.fake.spec);
        CHECK(lab.fake.spec->mail.size() == 1);
        CHECK(lab.fake.spec->sharepoint.size() == 1);
    }
    SECTION("a manifest tenant that differs from graph_tenant_id only in case")
    {
        json manifest = json::parse(lab_manifest_text());
        std::string tenant = kTenant;
        for (char& c : tenant) {
            c = static_cast<char>(c >= 'a' && c <= 'f' ? c - 'a' + 'A' : c);
        }
        REQUIRE(tenant != kTenant);
        manifest["tenant_id"] = tenant;
        lab.dir.write("seed-manifest.json", manifest.dump());
        const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK(run.err.empty());
    }
}

TEST_CASE("restore: an absent size is the config's; a flag overrides it", "[restore_command]")
{
    Harness lab(json{{"sample_mail", 3}, {"sample_sp", 0}, {"sample_od", 2}});

    SECTION("from the config")
    {
        const Run run = lab.run({"--run-id", kRunId});
        CHECK(run.exit_code == rp::exit_code::ok);
        REQUIRE(lab.fake.spec);
        // 3 mails: 2 canaries and 1 random (none in the pool); 2 OneDrive: 1 and 1.
        CHECK(lab.fake.spec->mail.size() == 2);
        CHECK(lab.fake.spec->sharepoint.empty());
        CHECK(lab.fake.spec->onedrive.size() == 1);
        CHECK_THAT(run.out,
                   ContainsSubstring("  mail        3          2 of 2    0 of 1  random shortfall\n"));
    }
    SECTION("from the flags")
    {
        const Run run = lab.run({"--run-id", kRunId, "--sp", "1", "--mail", "007"});
        CHECK(run.exit_code == rp::exit_code::ok);
        REQUIRE(lab.fake.spec);
        CHECK(lab.fake.spec->mail.size() == 4);
        CHECK(lab.fake.spec->sharepoint.size() == 1);
        CHECK(lab.fake.spec->onedrive.size() == 1);
    }
}

TEST_CASE("restore: without --run-id a run ID is made; with it, it is reused and its seed shown",
          "[restore_command]")
{
    Harness lab;
    SECTION("made")
    {
        const Run run = lab.run({"--mail", "1", "--sp", "0", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK(lab.run_id_calls == 1);
        CHECK_THAT(run.out, ContainsSubstring("\nrun " + kGeneratedRunId + "  seed " +
                                              seed_of(kGeneratedRunId) + "\ncanary cursor "));
    }
    SECTION("reused")
    {
        const Run run = lab.run({"--run-id", "repeat-me", "--mail", "1", "--sp", "0", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK(lab.run_id_calls == 0);
        CHECK_THAT(run.out, ContainsSubstring("\nrun repeat-me  seed " + seed_of("repeat-me") +
                                              "\ncanary cursor "));
    }
}

TEST_CASE("restore: the canary cursor picks where each rotation starts and the next is shown",
          "[restore_command]")
{
    Harness lab;

    const Run run = lab.run({"--run-id", kRunId, "--canary-cursor", "19,9,0", "--mail", "4",
                             "--sp", "1", "--od", "1"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK_THAT(run.out, ContainsSubstring("\ncanary cursor 19,9,0 -> 1,0,1\n"));
    REQUIRE(lab.fake.spec);
    REQUIRE(lab.fake.spec->mail.size() == 2);
    CHECK(lab.fake.spec->mail[0].subject == "RP-CANARY-0020");
    CHECK(lab.fake.spec->mail[1].subject == "RP-CANARY-0001");
    CHECK(lab.fake.spec->sharepoint.at(0).name == "rp-canary-10.png");
}

TEST_CASE("restore: a shortfall is named in the header, and is still a success", "[restore_command]")
{
    const auto [pool, sizes, row] = GENERATE(table<int, Args, std::string>({
        {0, Args{"--mail", "2"}, "  mail        2          1 of 1    0 of 1  random shortfall\n"},
        {2, Args{"--mail", "4"}, "  mail        4          1 of 2    2 of 2  canary shortfall\n"},
        {0, Args{"--mail", "4"},
         "  mail        4          1 of 2    0 of 2  canary and random shortfall\n"},
    }));
    Harness lab;
    lab.dir.write("seed-manifest.json", trimmed_manifest(1, 1, 1));
    for (int n = 1; n <= pool; ++n) {
        lab.fake.pool.mail.push_back(carol_mail(n));
    }
    Args args = sizes;
    args.insert(args.end(), {"--run-id", kRunId, "--sp", "0", "--od", "0"});

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK_THAT(run.out, ContainsSubstring(row));
    CHECK_THAT(run.out, ContainsSubstring("\nstatus succeeded: "));
}

TEST_CASE("restore: each item's row: its source, outcome, session time and message",
          "[restore_command]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.fake.answer = [](const connector::RestoreSpec&) {
        using connector::ItemKind;
        using connector::ItemOutcome;
        connector::RestoreResult result;
        result.status = connector::RestoreStatus::partial;
        result.items_sent = 3;
        result.items_restored = 1;
        result.session_ids = {"s-ok", "s-bad", "s-back"};
        result.sessions = {
            {"s-ok", ItemKind::mail, "Warning", "", "2026-09-30T10:00:00Z", "2026-09-30T11:02:03Z", 2, 1},
            {"s-bad", ItemKind::sharepoint, "Failed", "", "2026-09-30T10:00:00Z", "not a time", 1, 0},
            {"s-back", ItemKind::onedrive, "Failed", "", "2026-09-30T10:00:01Z", "2026-09-30T10:00:00Z", 0, 0},
        };
        result.items = {
            {ItemKind::mail, "RP-CANARY-0001", "s-ok", ItemOutcome::restored, "", false},
            {ItemKind::mail, "real\tmail\n01", "s-ok", ItemOutcome::failed,
             "Veeam could not reach\r\nMicrosoft 365", true},
            {ItemKind::sharepoint, "rp-canary-01.pdf", "s-bad", ItemOutcome::unknown, "", false},
            {ItemKind::mail, "an extra", "s-gone", ItemOutcome::unknown, "", false},
            {ItemKind::onedrive, "", "", ItemOutcome::unknown, "", false},
        };
        return result;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    // The infrastructure failure makes it an error.
    CHECK(run.exit_code == rp::exit_code::service);
    CHECK_THAT(run.err, StartsWith("restore error: 1 item(s) failed for an infrastructure reason"));
    const std::string tables = run.out.substr(expected_header().size());
    CHECK(tables ==
          "\n"
          "  KIND        SOURCE  NAME              OUTCOME                  SESSION  ELAPSED  MESSAGE\n"
          "  mail        canary  RP-CANARY-0001    restored                 s-ok     1:02:03  -\n"
          "  mail        random  real mail 01      failed (infrastructure)  s-ok     1:02:03  Veeam could not reach  Microsoft 365\n"
          "  sharepoint  canary  rp-canary-01.pdf  unknown                  s-bad    -        -\n"
          "  mail        -       an extra          unknown                  s-gone   -        -\n"
          "  onedrive    -       -                 unknown                  -        -        -\n"
          "\n"
          "  SESSION  KIND        RESULT   RESTORED  STARTED               ENDED                 ELAPSED\n"
          "  s-ok     mail        Warning  1 of 2    2026-09-30T10:00:00Z  2026-09-30T11:02:03Z  1:02:03\n"
          "  s-bad    sharepoint  Failed   0 of 1    2026-09-30T10:00:00Z  not a time            -\n"
          "  s-back   onedrive    Failed   0 of 0    2026-09-30T10:00:01Z  2026-09-30T10:00:00Z  -\n"
          "\n"
          "status partial: 1 of 3 item(s) restored in 0:02:03\n");
}

TEST_CASE("restore: a session's elapsed time is cut to whole seconds and never overflows",
          "[restore_command]")
{
    using namespace std::chrono;
    // 1678 and 2261 are the ends of what a time in nanoseconds holds; the span
    // between them is more nanoseconds than a signed 64-bit count holds.
    const seconds span =
        (sys_days{year{2261} / 12 / 31} + 23h + 59min + 59s) - sys_days{year{1678} / 1 / 1};
    const std::string hours = std::to_string(span.count() / 3600);
    const auto [started, ended, elapsed] = GENERATE_COPY(table<std::string, std::string, std::string>({
        {"1678-01-01T00:00:00Z", "2261-12-31T23:59:59Z", hours + ":59:59"},
        {"1678-01-01T00:00:00.5Z", "2261-12-31T23:59:59.25Z", hours + ":59:58"},
        {"2261-12-31T23:59:59Z", "1678-01-01T00:00:00Z", "-"},
        {"2026-09-30T10:00:00.9Z", "2026-09-30T10:00:01.1Z", "0:00:00"},
        {"2026-09-30T10:00:00.1Z", "2026-09-30T10:00:01.9Z", "0:00:01"},
        {"2026-09-30T10:00:01.1Z", "2026-09-30T10:00:01Z", "-"},
        {"not a time", "2026-09-30T10:00:01Z", "-"},
        {"", "2026-09-30T10:00:01Z", "-"},
    }));
    CAPTURE(started, ended);
    Harness lab;
    lab.fake.answer = [=](const connector::RestoreSpec& spec) {
        connector::RestoreResult result = restored(spec);
        result.sessions.at(0).started_at = started;
        result.sessions.at(0).ended_at = ended;
        return result;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    // The item's row and the session's row.
    CHECK_THAT(run.out, ContainsSubstring("sess-mail  " + elapsed + " "));
    CHECK_THAT(run.out, ContainsSubstring(ended + "  " + elapsed + "\n"));
}

TEST_CASE("restore: log lines go to the logger, never to stdout; without one the command's "
          "own is used",
          "[restore_command]")
{
    Harness lab;
    SECTION("the env's logger")
    {
        const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK_THAT(run.out, !ContainsSubstring("SENTINEL-LOG-LINE"));
        CHECK_THAT(run.err, !ContainsSubstring("SENTINEL-LOG-LINE"));
        CHECK_THAT(lab.log(), ContainsSubstring("SENTINEL-LOG-LINE"));
        CHECK(lab.fake.logger == lab.logger);
    }
    SECTION("none given")
    {
        rp::RestoreCommandEnv env = lab.env();
        env.connector_options.logger = nullptr;
        std::ostringstream out;
        std::ostringstream err;
        const std::string path_arg = utf8(lab.config_path);
        lab.fake.out = &out;
        const int code = rp::run_restore_command(
            Args{"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0", "--config", path_arg},
            out, err, env);
        lab.fake.out = nullptr;
        CHECK(code == rp::exit_code::ok);
        REQUIRE(lab.fake.logger);
        CHECK(lab.fake.logger != lab.logger);
        CHECK(lab.fake.logger->name() == "rpworker");
        CHECK_THAT(out.str(), !ContainsSubstring("SENTINEL-LOG-LINE"));
    }
}

TEST_CASE("restore: elapsed times are H:MM:SS, cut to whole seconds", "[restore_command]")
{
    const auto [elapsed, text] = GENERATE(table<std::chrono::nanoseconds, std::string>({
        {0ns, "0:00:00"},
        {999ms, "0:00:00"},
        {59s + 999ms, "0:00:59"},
        {3723s, "1:02:03"},
        {100h + 1s, "100:00:01"},
        {-1ns, "-"},
    }));
    CHECK(rp::format_elapsed(elapsed) == text);
}

TEST_CASE("restore: a made run ID is rp-<UTC time>-<8 hex digits> and passes check_run_id",
          "[restore_command]")
{
    const std::string first = rp::make_run_id();
    const std::string second = rp::make_run_id();
    CHECK(std::regex_match(first, std::regex{"rp-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}"}));
    CHECK_NOTHROW(sampling::check_run_id(first));
    // 32 random bits each: equal only by a 1 in 2^32 chance within one second.
    CHECK(first != second);

    // The time is UTC now: read it back and compare it with the system clock
    // (UTC), which a local time would miss by the zone's offset.
    using namespace std::chrono;
    const auto number = [&](std::size_t at, std::size_t n) { return std::stoi(first.substr(at, n)); };
    const year_month_day date{year{number(3, 4)}, month{static_cast<unsigned>(number(7, 2))},
                              day{static_cast<unsigned>(number(9, 2))}};
    REQUIRE(date.ok());
    const sys_seconds made =
        sys_days{date} + hours{number(12, 2)} + minutes{number(14, 2)} + seconds{number(16, 2)};
    const auto off = system_clock::now() - made;
    CHECK(off >= -1min);
    CHECK(off <= 1min);
}

TEST_CASE("restore: the default environment reads the real config and secrets, with a stderr "
          "logger",
          "[restore_command]")
{
    const rp::RestoreCommandEnv env = rp::default_restore_command_env();
    CHECK(env.default_config_path);
    CHECK(env.load_secrets);
    CHECK_FALSE(env.make_connector); // the default registry's veeam_m365
    CHECK_FALSE(env.make_run_id);    // rp::make_run_id
    CHECK_FALSE(env.now);            // steady_clock::now
    REQUIRE(env.connector_options.logger);
    CHECK(env.connector_options.logger->name() == "rpworker");
}

// --- Through the real veeam_m365 connector -------------------------------------------

namespace {

namespace vrl = rp::test::veeam_restore_lab;

// The command on the default registry's connector (env.make_connector null),
// its Veeam and Graph on `rig`'s recorded answers.
struct RealRig {
    RealRig()
    {
        config_path = dir.write("config.json", config_values().dump(2));
        dir.write("seed-manifest.json", lab_manifest_text());
    }

    rp::RestoreCommandEnv env()
    {
        rp::RestoreCommandEnv env;
        env.default_config_path = [] { return std::filesystem::path{"unused.json"}; };
        env.load_secrets = [] {
            return rp::Secrets{vrl::kUsername, vrl::kPassword, rp::test::graph_lab::pfx_base64(),
                               std::string{rp::test::graph_lab::kPfxPassword}};
        };
        connector::ConnectorOptions& o = env.connector_options;
        o.make_http = [this](const rp::HttpClientOptions&) -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(rig.veeam);
        };
        o.make_graph_http =
            [this](std::shared_ptr<spdlog::logger>) -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(rig.lab.graph_http);
        };
        o.logger = rig.logger;
        o.now = [this] { return rig.clock.now(); };
        o.sleep = [this](std::chrono::milliseconds wait) { rig.clock.sleep(wait); };
        o.jitter = [] { return 0.0; };
        // The recorded restore POST's time; before any is served, the time
        // the Worker app's test certificate is made for.
        o.wall_now = [this] {
            const auto posted = rig.next_post_time();
            return posted == std::chrono::system_clock::time_point{} ? rp::test::graph_lab::kNow
                                                                     : posted;
        };
        o.cert_exporter = rig.exporter;
        env.now = [this] { return rig.clock.now(); };
        return env;
    }

    Run run(Args args)
    {
        const std::string path_arg = utf8(config_path);
        args.push_back("--config");
        args.push_back(path_arg);
        std::ostringstream out;
        std::ostringstream err;
        const int code = rp::run_restore_command(args, out, err, env());
        return {code, out.str(), err.str()};
    }

    rp::test::TempDir dir;
    std::filesystem::path config_path;
    vrl::RestoreRig rig;
};

} // namespace

TEST_CASE("restore through veeam_m365: Veeam unreachable is exit 3 and nothing is restored",
          "[restore_command][veeam_m365]")
{
    RealRig real;
    real.rig.veeam.on(rp::HttpMethod::post, vrl::url("/v8/token"),
                      [](const rp::HttpRequest& request) -> rp::HttpResponse {
                          throw rp::HttpError("POST " + request.url + ": could not connect",
                                              rp::TransportError::connect, 0, 1);
                      });

    const Run run = real.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::transient);
    CHECK(run.out.empty());
    CHECK_THAT(run.err, StartsWith("restore error: "));
    CHECK_THAT(run.err, !ContainsSubstring(vrl::kPassword));
    CHECK(real.rig.restore_posts().empty());
}

TEST_CASE("restore through veeam_m365: the target guard refuses a wrong target, exit 4, "
          "before any restore request",
          "[restore_command][veeam_m365][target_guard]")
{
    RealRig real;
    real.rig.lab.serve_edited(rp::test::graph_lab::drive_url(), "restoretarget-drive-200",
                              [](json& body) { body["name"] = "Dokumenty"; });

    const Run run = real.run({"--run-id", kRunId, "--mail", "0", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::service);
    // docs/worker-config.md's error example.
    CHECK(run.err == "restore error: target guard: the drive test_library_id names is "
                     "\"Dokumenty\", not \"RestoreTarget\": the Worker restores only into the "
                     "RestoreTarget library; nothing was restored\n");
    // The header was out; nothing was sent to restore.
    CHECK_THAT(run.out,
               StartsWith("restore point " + vrl::kBackupTime + "  " + vrl::kRestorePointId));
    // Veeam saw only what comes before the guard: the sign-in, the restore
    // points (a canary-only sample lists no candidates) and the sign-out. No
    // explore session, no restore session list, no restore POST.
    std::vector<std::string> veeam_calls;
    for (const rp::HttpRequest& request : real.rig.veeam.requests()) {
        const std::string path = request.url.substr(vrl::kBase.size());
        veeam_calls.push_back(std::string{rp::to_string(request.method)} + " " +
                              path.substr(0, path.find('?')));
    }
    CHECK(veeam_calls == std::vector<std::string>{
                             "POST /v8/token",
                             "GET /v8/Organizations",
                             "GET /v8/RestorePoints",
                             "POST /v8/token/logout",
                         });
    CHECK(real.rig.restore_posts().empty());
    CHECK(real.rig.exporter->calls == 0);
}

TEST_CASE("restore through veeam_m365: a canary restored on the recorded run, exit 0",
          "[restore_command][veeam_m365]")
{
    RealRig real;
    real.rig.serve(vrl::mail_x1());

    // RP-CANARY-0011, bob's first, is the manifest's mail canary 10: W2.4's
    // recorded single-mail restore.
    const Run run = real.run({"--run-id", kRunId, "--canary-cursor", "10,0,0", "--mail", "1",
                              "--sp", "0", "--od", "0"});

    INFO(run.out);
    INFO(run.err);
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    // docs/worker-config.md's example ("rpworker restore"): keep them in step.
    CHECK(run.out ==
          "restore point 2026-09-27T22:00:48.1447833Z  "
          "c2f0f2e7-177f-48ac-992b-93a50cf702e35e1c0a24-0000-4000-8000-000000000924  "
          "(veeam_org_name RestoreProofLab.onmicrosoft.com)\n"
          "run run-0001  seed " + seed_of(kRunId) + "\n"
          "canary cursor 10,0,0 -> 11,0,0\n"
          "  KIND        REQUESTED  CANARIES  RANDOM  NOTE\n"
          "  mail        1          1 of 1    0 of 0\n"
          "  sharepoint  0          0 of 0    0 of 0\n"
          "  onedrive    0          0 of 0    0 of 0\n"
          "restoring 1 item(s) ...\n"
          "\n"
          "  KIND  SOURCE  NAME            OUTCOME   SESSION                               ELAPSED  MESSAGE\n"
          "  mail  canary  RP-CANARY-0011  restored  b6fe35ef-9633-481d-9756-3496a717d8a9  0:00:32  "
          "Item RP-CANARY-0011 was restored successfully (type: IPM.Note; source: Bob Test\\Inbox; "
          "target: restoretest@RestoreProofLab.onmicrosoft.com\\<null>\\Inbox)\n"
          "\n"
          "  SESSION                               KIND  RESULT   RESTORED  STARTED                       ENDED                         ELAPSED\n"
          "  b6fe35ef-9633-481d-9756-3496a717d8a9  mail  Success  1 of 1    2026-09-28T21:27:28.3281642Z  2026-09-28T21:28:00.6973119Z  0:00:32\n"
          "\n"
          "status succeeded: 1 of 1 item(s) restored in 0:00:05\n");
    CHECK(real.rig.restore_posts().size() == 1);
    CHECK(real.rig.exporter->calls == 1);
    CHECK_THAT(run.out, !ContainsSubstring(vrl::kPassword));
    CHECK_THAT(run.out, !ContainsSubstring(vrl::kFakePfxPassword));
}
