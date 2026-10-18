// `rpworker doctor` (W7.2, docs/decisions.md 2026-10-18): the command's reads
// and their order over a fake machine (DoctorEnv), Veeam's and Graph's
// recorded answers, a test TSA and a Cloud that answers /v1/version, in a
// temp folder standing for %ProgramData%\RestoreProof. Nothing here touches
// %ProgramData%, the SCM, LocalMachine\My or the network. The lines' words
// are doctor_test.cpp's; here, which facts reach them.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "result_lab.hpp"
#include "schema_walk.hpp"
#include "signing_lab.hpp"
#include "test_support.hpp"
#include "tsa_lab.hpp"

#include <rp/base64.hpp>
#include <rp/cli.hpp>
#include <rp/cloud_api.hpp>
#include <rp/doctor.hpp>
#include <rp/doctor_command.hpp>
#include <rp/service.hpp>
#include <rp/service_recovery.hpp>
#include <rp/signer.hpp>
#include <rp/vault.hpp>

#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;
using nlohmann::json;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::doctor::Ace;
using rp::doctor::Security;
using rp::test::load_fixture;
using rp::test::make_response;
using Args = std::vector<std::string_view>;
using namespace rp::test::graph_lab;
using namespace std::chrono_literals;

namespace {

const std::string kVeeam = "https://veeam.test:4443";
const std::string kCloud = "https://cloud.test";
const std::string kTsa = "http://tsa.test/";
const std::string kThumb = "AC3220B58A2B4C438DA13816C2DD1E25D1F783A7";
const std::string kOrgId = "ff96d072-29e2-4cb4-a155-2590f5473176";
const std::string kWorkerId = "11111111-2222-4333-8444-555555555555";

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

const rp::test::TestTsa& tsa()
{
    static const rp::test::TestTsa instance;
    return instance;
}

std::size_t count_of(const std::string& text, std::string_view what)
{
    std::size_t n = 0;
    for (std::size_t at = text.find(what); at != std::string::npos; at = text.find(what, at + 1)) {
        ++n;
    }
    return n;
}

std::string signing_key_id()
{
    return rp::SigningKey::from_base64(rp::test::kSigningKey1Base64)->key_id();
}

std::string jwt_with_roles(const std::vector<std::string>& roles)
{
    return rp::base64url_encode(std::string(R"({"alg":"RS256","typ":"JWT"})")) + "." +
           rp::base64url_encode(json{{"roles", roles}}.dump()) + "." +
           rp::base64url_encode(std::string(32, '\0'));
}

HttpResponse token_with(const std::vector<std::string>& roles)
{
    json fixture = rp::test::load_fixture_json("graph", "token-200");
    fixture["body"]["access_token"] = jwt_with_roles(roles);
    return rp::test::to_response(fixture);
}

Ace allow(std::string sid, std::uint32_t mask, bool children = true)
{
    return Ace{std::move(sid), true, mask, children, false, false};
}

class FakeExporter final : public rp::CertificateExporter {
public:
    explicit FakeExporter(std::optional<rp::CertExportFailure> failure) : failure_(failure) {}
    rp::ExportedPfx export_pfx(std::string_view) override
    {
        if (failure_) {
            throw rp::CertExportError("certificate x: refused", *failure_);
        }
        rp::ExportedPfx pfx;
        pfx.pfx_base64 = "UEZY";
        pfx.password = "pw";
        return pfx;
    }

private:
    std::optional<rp::CertExportFailure> failure_;
};

struct Run {
    int exit_code;
    std::string out;
    std::string err;

    bool has(std::string_view line) const { return out.find(std::string(line) + "\n") != std::string::npos; }
    bool has_problem(std::string_view id_text) const
    {
        return out.find("problem: " + std::string(id_text)) != std::string::npos;
    }
};

// A Worker as the installer leaves it, in a temp folder, with a Veeam, a
// Cloud, a TSA and the lab's Graph answering as they should.
struct Lab {
    Lab()
    {
        for (const char* name : {"state", "runs", "outbox", "sent", "failed", "logs"}) {
            std::filesystem::create_directories(data / name);
        }
        write("tsa.pem", tsa().root_pem());
        write_config();
        write("state/worker.json",
              rp::worker_record_text({kWorkerId, signing_key_id(), kCloud, "2026-10-16T16:00:00Z"}));
        write("logs/worker.log", std::string(1024, 'x'));
        write("vault.bin", "x");
        profile = dir.write("profile.json", lab_profile().dump());

        http.on(HttpMethod::post, kVeeam + "/v8/token", {veeam_token()});
        http.on(HttpMethod::get, kVeeam + "/v8/Organizations?limit=1000&offset=0",
                {load_fixture("veeam", "organizations-200")});
        http.on(HttpMethod::get,
                kVeeam + "/v8/RestorePoints?organizationId=" + kOrgId + "&limit=1000&offset=0",
                {load_fixture("veeam", "restore-points-200")});
        http.on(HttpMethod::post, kVeeam + "/v8/token/logout", {load_fixture("veeam", "logout-204")});
        http.on(HttpMethod::get, kCloud + "/v1/version", [](const HttpRequest& request) {
            HttpResponse response = make_response(200, R"({"api":1,"version":"0.1.0"})");
            response.headers[std::string(rp::kCloudApiHeader)] = "1";
            // Never a token on this route.
            response.headers["x-saw-authorization"] = request.headers.contains("Authorization") ? "yes" : "no";
            return response;
        });
        http.on(HttpMethod::post, kTsa, [](const HttpRequest& request) {
            return make_response(200, tsa().respond(request.body), "application/timestamp-reply");
        });
        http.on(HttpMethod::get, std::string(rp::kEntraReachUrl), {make_response(200, "{}")});
        http.on(HttpMethod::get, std::string(rp::kGraphReachUrl), {make_response(401, "{}")});

        graph.on(HttpMethod::post, kTokenUrl, {token_with({"Sites.Selected", "Files.SelectedOperations.Selected",
                                                           "Lists.SelectedOperations.Selected"})});
        graph.on(HttpMethod::get, inbox_url(), {load_fixture("graph", "mailbox-inbox-200")});
        graph.on(HttpMethod::get, mail_list_url(false), {load_fixture("graph", "mail-list-200-empty")});
        graph.on(HttpMethod::get, drive_url(), {load_fixture("graph", "restoretarget-drive-200")});
        serve_library_root(graph);
        graph.on(HttpMethod::get, library_children_url(),
                 {load_fixture("graph", "restoretarget-children-200-empty")});
        graph.on(HttpMethod::get, folder_url(), {load_fixture("graph", "onedrive-folder-200")});
        graph.on(HttpMethod::get, folder_children_url(), {load_fixture("graph", "onedrive-children-200-empty")});
    }

    static HttpResponse veeam_token()
    {
        json fixture = rp::test::load_fixture_json("veeam", "token-200");
        fixture["body"]["access_token"] = "SENTINEL-DOCTOR-ACCESS";
        fixture["body"]["refresh_token"] = "SENTINEL-DOCTOR-REFRESH";
        return rp::test::to_response(fixture);
    }

    static json lab_profile()
    {
        const Lab_values& v = lab_values();
        return json{{"format", std::string{rp::kClientProfileFormat}},
                    {"veeam_org_name", "RestoreProofLab.onmicrosoft.com"},
                    {"graph_tenant_id", kTenant},
                    {"graph_client_id", kClient},
                    {"test_mailbox", v.mailbox},
                    {"test_site_id", v.site_id},
                    {"test_library_id", v.library_id},
                    {"test_onedrive_drive_id", v.onedrive_drive_id},
                    {"test_onedrive_folder_id", v.folder_id}};
    }

    void write(const std::string& name, std::string_view text) const
    {
        std::ofstream file(data / name, std::ios::binary);
        file.write(text.data(), static_cast<std::streamsize>(text.size()));
        REQUIRE(file);
    }

    void write_config(const std::string& extra = "")
    {
        write("config.json", "{" + extra + R"("cloud_url": ")" + kCloud + R"(", "veeam_url": ")" + kVeeam +
                                 R"(", "tsa_url": ")" + kTsa + R"(", "tsa_ca_file": )" +
                                 json(utf8(data / "tsa.pem")).dump() + "}");
    }

    Security security_of(const std::filesystem::path& p) const
    {
        if (const auto it = securities.find(p); it != securities.end()) {
            return it->second;
        }
        Security s;
        s.present = s.readable = true;
        s.owner_sid = std::string(rp::doctor::kSidAdministrators);
        const std::string svc = *rp::doctor::service_sid(rp::kServiceName);
        if (p == data) {
            s.is_protected = true;
            s.aces = {allow("S-1-5-18", rp::doctor::kRightsFull), allow("S-1-5-32-544", rp::doctor::kRightsFull),
                      allow(svc, rp::doctor::kRightsReadExecute)};
        } else if (p.parent_path() == data && p.filename() == "vault.bin") {
            s.is_protected = true;
            s.aces = {allow("S-1-5-18", rp::doctor::kRightsFull, false),
                      allow("S-1-5-32-544", rp::doctor::kRightsFull, false),
                      allow("S-1-3-4", rp::doctor::kRightsFull, false), allow(svc, rp::doctor::kRightsRead, false)};
        } else if (p.parent_path() == data && std::filesystem::is_directory(p)) {
            s.aces = {allow(svc, rp::doctor::kRightsModify)};
        } else {
            s.aces = {Ace{"S-1-5-32-544", true, rp::doctor::kRightsFull, false, false, true}};
        }
        return s;
    }

    rp::DoctorEnv env()
    {
        rp::DoctorEnv e;
        e.data_dir = [this] {
            if (data_throws) {
                throw std::runtime_error("no data folder");
            }
            return data;
        };
        e.program_data = [this] { return dir.path(); };
        e.installed_exe = [this] { return installed; };
        e.own_exe = [this] { return own; };
        e.elevated = [this] {
            if (on_elevated) {
                on_elevated();
            }
            return elevated;
        };
        e.windows_build = [] { return std::string("10.0.20348"); };
        e.host_name = [this] { return host; };
        e.now = [] { return std::chrono::system_clock::from_time_t(rp::test::kTestTsaTime) + 30s; };
        e.load_secrets = [this](const std::filesystem::path& vault) -> rp::Secrets {
            vault_read = vault;
            if (vault_error) {
                throw rp::VaultError(utf8(vault) + ": vault file not found");
            }
            return secrets;
        };
        e.read_security = [this](const std::filesystem::path& p) { return security_of(p); };
        e.access_for = [this](const std::filesystem::path& p, std::string_view sid,
                              const std::vector<std::string>& groups) -> std::optional<std::uint32_t> {
            CHECK(sid == *rp::doctor::service_sid(rp::kServiceName));
            CHECK(groups == rp::doctor::service_token_groups());
            if (const auto it = access.find(p); it != access.end()) {
                return it->second;
            }
            return rp::doctor::kRightsFull;
        };
        e.logon_rights = [] { return rp::doctor::LogonFacts{std::vector<std::string>{"S-1-5-80-0"}, {}}; };
        e.free_bytes = [](const std::filesystem::path&) { return std::optional<std::uint64_t>(std::uint64_t{20} << 30); };
        e.account_name = [](std::string_view sid) { return "name of " + std::string(sid); };
        e.machine_certificate = [this](std::string_view thumbprint) {
            seen_thumbprints.emplace_back(thumbprint);
            return certificate;
        };
        e.exporter = [this] { return std::make_shared<FakeExporter>(export_failure); };
        e.read_setup = [this](std::string_view name, rp::ServiceSetup& setup) {
            CHECK(name == rp::kServiceName);
            if (installed_service) {
                setup = rp::service_setup(rp::kServiceName, "\"" + utf8(installed) + "\" service run");
                return rp::ScmResult{};
            }
            return rp::ScmResult{1060, rp::ScmStep::service};
        };
        e.query_service = [](std::string_view, rp::ServiceStatus& status) {
            status.state = rp::ServiceState::running;
            return rp::ScmResult{};
        };
        e.make_http = [this](const rp::HttpClientOptions& options) -> std::unique_ptr<rp::IHttpClient> {
            http_options.push_back(options);
            return std::make_unique<rp::test::ForwardingHttpClient>(http);
        };
        e.make_graph_http = [this](std::shared_ptr<spdlog::logger>) -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(graph);
        };
        e.veeam_options.sleep = [](std::chrono::milliseconds) {};
        e.veeam_options.jitter = [] { return 0.0; };
        e.graph_options.now = [] { return std::chrono::steady_clock::time_point{}; };
        e.graph_options.wall_now = [] { return std::chrono::system_clock::from_time_t(rp::test::kTestTsaTime); };
        e.graph_options.sleep = [](std::chrono::milliseconds) {};
        e.graph_options.jitter = [] { return 0.0; };
        return e;
    }

    Run run(Args args)
    {
        std::ostringstream out;
        std::ostringstream err;
        const int code = rp::run_doctor_command(args, out, err, env());
        return {code, out.str(), err.str()};
    }

    Run run_with_client()
    {
        const std::string profile_arg = utf8(profile);
        return run({"--client", profile_arg});
    }

    rp::test::TempDir dir;
    std::filesystem::path data = dir.path() / "RestoreProof";
    std::filesystem::path installed = dir.path() / "Program Files" / "RestoreProof" / "rpworker.exe";
    std::filesystem::path own = installed;
    std::filesystem::path profile;
    bool elevated = true;
    bool data_throws = false;
    bool vault_error = false;
    bool installed_service = true;
    std::function<void()> on_elevated;
    std::optional<std::string> host = "veeam.test";
    rp::Secrets secrets{"DESKTOP\\rp-veeam",
                        "Sentinel-Doctor-Veeam-Password",
                        pfx_base64(),
                        kPfxPassword,
                        std::string(rp::test::kSigningKey1Base64),
                        std::nullopt,
                        std::string(43, 'A')};
    std::map<std::filesystem::path, Security> securities;
    std::map<std::filesystem::path, std::uint32_t> access;
    std::optional<rp::CertExportFailure> export_failure;
    rp::DoctorCertificate certificate{true,
                                      std::chrono::system_clock::from_time_t(rp::test::kTestTsaTime) + 800 * 24h,
                                      std::filesystem::path("C:\\PD\\Microsoft\\Crypto\\RSA\\MachineKeys\\76c3")};
    std::vector<std::string> seen_thumbprints;
    std::filesystem::path vault_read;
    std::vector<rp::HttpClientOptions> http_options;
    rp::test::FakeHttpClient http;
    rp::test::FakeHttpClient graph;
};

} // namespace

// --- The command line, and what is refused before anything is read --------------------

TEST_CASE("doctor: arguments it doesn't understand are usage, exit 64", "[doctor_command]")
{
    const Args args = GENERATE(Args{"--client"}, Args{"--client", ""}, Args{"--config", "a", "--config", "b"},
                               Args{"--vault", "a", "--vault", "b"}, Args{"--json", "a", "--json", "b"},
                               Args{"--record", "a", "--record", "b"}, Args{"--hash"}, Args{"--hash", "x"}, Args{"list"},
                               Args{"--config"});
    Lab lab;
    const Run run = lab.run(args);
    CHECK(run.exit_code == 64);
    CHECK(run.out.empty());
    CHECK(run.err == std::string(rp::kCliUsage));
}

TEST_CASE("doctor: --json refused before anything is read", "[doctor_command]")
{
    Lab lab;
    lab.elevated = false; // never asked
    lab.on_elevated = [] { FAIL("read before --json was checked"); };
    const std::string exists = utf8(lab.dir.write("there.json", "{}"));
    const std::string no_folder = utf8(lab.dir.path() / "none" / "d.json");
    const std::string device = utf8(lab.dir.path() / "con");
    struct Row {
        std::string arg;
        std::string why;
    };
    const Row row = GENERATE_COPY(Row{exists, "the file already exists"}, Row{no_folder, "the folder doesn't exist"},
                                  Row{device, "not a file name"},
                                  Row{"\xff.json", "not a UTF-8 path"});
    const Run run = lab.run({"--json", row.arg});
    CHECK(run.exit_code == 1);
    CHECK(run.out.empty());
    CHECK_THAT(run.err, StartsWith("doctor error: --json "));
    CHECK_THAT(run.err, ContainsSubstring(": " + row.why + "\n"));
}

TEST_CASE("doctor: not elevated is one line, the summary and exit 5, nothing else read",
          "[doctor_command]")
{
    Lab lab;
    lab.elevated = false;
    const Run run = lab.run({});
    CHECK(run.exit_code == 5);
    CHECK(run.out == "problem: doctor: not run from an elevated prompt (fix: open PowerShell as Administrator "
                     "and run rpworker doctor again)\n"
                     "doctor: 0 ok, 0 warning(s), 1 problem(s), 0 skipped\n");
    CHECK(run.err.empty());
    CHECK(lab.http_options.empty());
}

// --- A healthy Worker -------------------------------------------------------------

TEST_CASE("doctor: a Worker as the installer leaves it has no problem, a client included",
          "[doctor_command]")
{
    Lab lab;
    const std::string json_file = utf8(lab.dir.path() / "doctor.json");
    const std::string profile_arg = utf8(lab.profile);
    const Run run = lab.run({"--client", profile_arg, "--json", json_file});
    INFO(run.out << " ERR: " << run.err);
    CHECK(run.err.empty());
    CHECK(run.exit_code == 0);
    CHECK(run.out.find("problem:") == std::string::npos);
    CHECK(run.has("ok: veeam: https://veeam.test:4443 is this machine"));
    CHECK(run.has("ok: cloud: RestoreProof Cloud 0.1.0, API 1"));
    CHECK(run.has("ok: tsa: http://tsa.test/ answered, token verified"));
    CHECK(run.has("ok: clock: 30 s from the TSA's time"));
    CHECK(run.has("ok: signing key: the one registered as worker " + kWorkerId));
    CHECK(run.has("ok: client 1: graph: the app's token carries Lists.SelectedOperations.Selected"));
    CHECK(run.has("ok: client 1: Veeam's organisation RestoreProofLab.onmicrosoft.com is this tenant's"));
    CHECK_THAT(run.out, ContainsSubstring("ok: veeam: RestoreProofLab.onmicrosoft.com: certificate " + kThumb +
                                          " exports (in memory, discarded), valid to "));
    CHECK(run.has("ok: veeam: RestoreProofLab.onmicrosoft.com: NT SERVICE\\RestoreProof can read the key file "
                  "C:\\PD\\Microsoft\\Crypto\\RSA\\MachineKeys\\76c3"));
    CHECK(lab.seen_thumbprints == std::vector<std::string>{kThumb});
    CHECK(lab.vault_read == lab.data / "vault.bin");
    // The order is the entry's, and every line appears before the summary.
    const std::vector<std::string> order{"ok: doctor:", "ok: config:", "ok: folders:", "ok: outbox:", "ok: disk:",
                                         "ok: log:",    "ok: vault:",  "ok: signing key:", "ok: service:",
                                         "ok: cloud:",  "ok: tsa:",    "ok: veeam:",  "ok: graph:", "ok: client 1:",
                                         "doctor: "};
    std::size_t at = 0;
    for (const std::string& start : order) {
        CAPTURE(start);
        const std::size_t found = run.out.find(start, at);
        REQUIRE(found != std::string::npos);
        at = found;
    }
    // The Cloud's /v1/version took no token; the Veeam client had the config's pin and CA.
    CHECK(lab.http_options.size() >= 3);

    std::ifstream file(rp::test::widen(json_file), std::ios::binary);
    const json doc = json::parse(file);
    CHECK(doc["format"] == "restoreproof.doctor.v1");
    CHECK(doc["worker_id"] == kWorkerId);
    CHECK(doc["key_id"] == signing_key_id());
    CHECK(doc["windows_build"] == "10.0.20348");
    CHECK(doc["elevated"] == true);
    CHECK(doc["counts"]["problem"] == 0);
    // shared/schemas/doctor.v1.json: the subset both drafts read alike, and this file valid.
    const json schema = json::parse(rp::test::read_shared("schemas/doctor.v1.json"));
    CHECK(rp::test::problems_of(schema) == std::vector<std::string>{});
    CHECK(schema.at("properties").at("format").at("const") == std::string(rp::doctor::kDoctorFormat));
    nlohmann::json_schema::json_validator validator;
    validator.set_root_schema(schema);
    CHECK_NOTHROW(validator.validate(doc));
    const std::string text = doc.dump();
    for (const std::string_view secret : {"Sentinel-Doctor-Veeam-Password", "SENTINEL-DOCTOR", "RestoreProofLab",
                                          "veeam.test", "tsa.test", "C:\\\\PD"}) {
        CAPTURE(secret);
        CHECK(text.find(secret) == std::string::npos);
    }
}

TEST_CASE("doctor: without a client, Entra's and Graph's hosts are reached", "[doctor_command]")
{
    Lab lab;
    const Run run = lab.run({});
    CHECK(run.exit_code == 0);
    CHECK(run.has("ok: graph: login.microsoftonline.com reached"));
    CHECK(run.has("ok: graph: graph.microsoft.com reached"));
    CHECK(run.has("skip: graph: no client named (needs --client <profile file>)"));
}

// --- What each read finds -------------------------------------------------------------

TEST_CASE("doctor: a config that doesn't load skips what reads it", "[doctor_command]")
{
    Lab lab;
    lab.write("config.json", "{");
    const Run run = lab.run({});
    CHECK(run.exit_code == 5);
    CHECK(run.has_problem("config: "));
    CHECK(run.has("skip: cloud: the registration and /v1/version (needs config.load)"));
    CHECK(run.has("skip: tsa and clock: a token's time (needs config.load)"));
    CHECK(run.has("skip: veeam: the login, the organisations and their certificates (needs config.load)"));
}

TEST_CASE("doctor: a lab's config, a --config and --vault given", "[doctor_command]")
{
    Lab lab;
    std::string keys;
    const json profile = Lab::lab_profile();
    for (const auto& [key, value] : profile.items()) {
        if (key != "format") {
            keys += json(key).dump() + ": " + value.dump() + ", ";
        }
    }
    lab.write_config(R"("jobs_file": "C:\\lab\\jobs.json", )" + keys);
    const std::string config = utf8(lab.data / "config.json");
    const std::string vault = utf8(lab.dir.path() / "other-vault.bin");
    const Run run = lab.run({"--config", config, "--vault", vault});
    CHECK_THAT(run.out, ContainsSubstring("warning: config: jobs_file is set"));
    CHECK_THAT(run.out, ContainsSubstring("ok: config: the eight client keys are set"));
    CHECK(lab.vault_read == lab.dir.path() / "other-vault.bin");
}

TEST_CASE("doctor: a path that isn't UTF-8 is a doctor error", "[doctor_command]")
{
    Lab lab;
    const Run run = lab.run({"--config", "\xff"});
    CHECK(run.exit_code == 1);
    CHECK_THAT(run.err, StartsWith("doctor error: "));
}

TEST_CASE("doctor: an unexpected failure is said without its words", "[doctor_command]")
{
    Lab lab;
    lab.data_throws = true;
    const Run run = lab.run({});
    CHECK(run.exit_code == 1);
    CHECK(run.err == "error: unexpected failure\n");
}

TEST_CASE("doctor: the outbox's folders, a file among them, and an unlistable failed\\",
          "[doctor_command]")
{
    Lab lab;
    std::filesystem::create_directories(lab.data / "outbox" / "run-a");
    std::filesystem::create_directories(lab.data / "sent" / "run-b");
    lab.write("outbox/stray.txt", "x");
    std::filesystem::remove(lab.data / "failed");
    lab.write("failed", "a file where a folder belongs");
    lab.write("logs/worker.1.log", std::string(2048, 'y'));
    const Run run = lab.run({});
    CHECK(run.has("ok: outbox: 1 queued, 1 sent, 0 failed"));
    CHECK_THAT(run.out, ContainsSubstring("problem: outbox: " + utf8(lab.data / "failed") + " can't be listed"));
    CHECK(run.has("ok: log: " + utf8(lab.data / "logs" / "worker.log") + " 0 MiB, 0 MiB with the rotated files"));
}

TEST_CASE("doctor: a folder that isn't there and one the service can't change", "[doctor_command]")
{
    Lab lab;
    lab.securities[lab.data / "runs"] = Security{};
    lab.access[lab.data / "state"] = rp::doctor::kRightsRead;
    const Run run = lab.run({});
    CHECK(run.has_problem("folders: " + utf8(lab.data / "runs") + " is not there"));
    CHECK(run.has_problem("folders: " + utf8(lab.data / "state") + ": NT SERVICE\\RestoreProof can't change it"));
}

TEST_CASE("doctor: a vault that can't be read skips the key, Graph and the clients", "[doctor_command]")
{
    Lab lab;
    lab.vault_error = true;
    lab.securities[lab.data / "vault.bin"] = Security{};
    const Run run = lab.run_with_client();
    CHECK(run.has_problem("vault: " + utf8(lab.data / "vault.bin") + ": vault file not found"));
    CHECK(run.has("skip: signing key: its key_id (needs vault.read)"));
    CHECK(run.has("skip: graph: the Worker's certificate (needs vault.read)"));
    CHECK(run.has("skip: client 1: graph: the app's token and the three targets (needs graph.certificate)"));
    CHECK_THAT(run.out, ContainsSubstring("problem: veeam: veeam_username or veeam_password is not in the vault"));
}

TEST_CASE("doctor: the vault's entries are named by account", "[doctor_command]")
{
    Lab lab;
    const Run run = lab.run({});
    CHECK_THAT(run.out, ContainsSubstring("ok: vault: " + utf8(lab.data / "vault.bin") +
                                          ": entries for name of S-1-5-18, name of S-1-5-32-544, name of S-1-3-4, "
                                          "name of "));
}

TEST_CASE("doctor: a signing key that isn't one, and one that isn't the registered key", "[doctor_command]")
{
    Lab lab;
    lab.secrets.signing_key_base64 = "not a key";
    CHECK(lab.run({}).has_problem("signing key: signing_key_base64 is not an Ed25519 key"));
    Lab other;
    other.write("state/worker.json", rp::worker_record_text({kWorkerId, std::string(64, 'c'), kCloud,
                                                             "2026-10-16T16:00:00Z"}));
    CHECK(other.run({}).has_problem("signing key: key_id " + signing_key_id()));
    Lab none;
    std::filesystem::remove(none.data / "state" / "worker.json");
    CHECK(none.run({}).has_problem("cloud: this Worker isn't registered"));
    Lab garbled;
    garbled.write("state/worker.json", "{}");
    CHECK(garbled.run({}).has_problem("cloud: state\\worker.json can't be read"));
}

TEST_CASE("doctor: the service not installed, and a run in progress", "[doctor_command]")
{
    Lab lab;
    lab.installed_service = false;
    lab.securities[lab.installed] = Security{};
    lab.own = lab.dir.path() / "dev" / "rpworker.exe";
    const Run run = lab.run({});
    CHECK(run.has_problem("service: RestoreProof is not installed"));
    CHECK(run.out.find("warning: doctor: the service runs") == std::string::npos);

    Lab running;
    running.own = running.dir.path() / "dev" / "rpworker.exe";
    running.write("state/running.json",
                  "{\"format\":\"restoreproof.running.v1\",\"kind\":\"run\",\"run_id\":\"r1\"}");
    const Run garbled = running.run({});
    CHECK_THAT(garbled.out, ContainsSubstring("warning: doctor: the service runs " + utf8(running.installed)));
    CHECK_THAT(garbled.out, ContainsSubstring("warning: service: run (state\\running.json unreadable) in progress"));
}

TEST_CASE("doctor: a run record of the service's own, by its time", "[doctor_command]")
{
    Lab lab;
    rp::RunningRecord record = rp::new_run_record("7cc849e8-0000-4000-8000-000000000001", std::nullopt,
                                                  rp::read_client_profile_file(lab.profile),
                                                  std::chrono::system_clock::from_time_t(rp::test::kTestTsaTime) - 7h);
    lab.write("state/running.json", rp::record_text(record));
    const Run run = lab.run({});
    CHECK_THAT(run.out, ContainsSubstring("problem: service: run 7cc849e8-0000-4000-8000-000000000001 has been in "
                                          "progress for 7 h"));
}

TEST_CASE("doctor: the Cloud and the TSA unreachable", "[doctor_command]")
{
    Lab lab;
    const auto unreachable = [](const HttpRequest&) -> HttpResponse {
        throw rp::HttpError("no route", rp::TransportError::connect, 0, 1);
    };
    lab.http.on(HttpMethod::get, kCloud + "/v1/version", unreachable);
    lab.http.on(HttpMethod::post, kTsa, unreachable);
    const Run run = lab.run({});
    INFO(run.out << " ERR: " << run.err);
    CHECK(run.has("problem: cloud: https://cloud.test/v1/version: unreachable (fix: check cloud_url, the network "
                  "and cloud_ca_file)"));
    CHECK(run.has("problem: tsa: http://tsa.test/: no token (tsa_unreachable) (fix: check tsa_url and the network "
                  "to it)"));
    CHECK(run.has("skip: clock: against the TSA's time (needs tsa.token)"));
}

TEST_CASE("doctor: the default TSA, and a cloud_url ending in a slash", "[doctor_command]")
{
    Lab lab;
    lab.write("config.json", "{\"cloud_url\": \"" + kCloud + "/\", \"veeam_url\": \"" + kVeeam + "\"}");
    lab.http.on(HttpMethod::post, std::string(rp::kDefaultTsaUrl), {make_response(503, "")});
    const Run run = lab.run({});
    CHECK(run.has("ok: cloud: RestoreProof Cloud 0.1.0, API 1"));
    CHECK(run.has("problem: tsa: http://timestamp.digicert.com: no token (tsa_http_status) (fix: check tsa_url "
                  "and the network to it)"));
}

TEST_CASE("doctor: whether veeam_url is this machine", "[doctor_command]")
{
    struct Row {
        std::string url;
        std::optional<std::string> host;
        bool local;
    };
    const Row row = GENERATE(Row{"https://localhost:4443", std::nullopt, true},
                             Row{"https://127.0.0.1:4443", std::nullopt, true},
                             Row{"https://[::1]:4443", std::nullopt, true},
                             Row{"https://VEEAM.test:4443", std::string("veeam.TEST"), true},
                             Row{"https://veeam.test", std::nullopt, false},
                             Row{"https://other:4443", std::string("veeam.test"), false});
    CAPTURE(row.url);
    Lab lab;
    lab.host = row.host;
    lab.write("config.json", "{\"cloud_url\": \"" + kCloud + "\", \"veeam_url\": \"" + row.url + "\"}");
    lab.http.on(HttpMethod::post, row.url.substr(0, row.url.find('/', 8)) + "/v8/token",
                {make_response(401, "{}")});
    const Run run = lab.run({});
    CHECK(run.out.find(row.local ? "ok: veeam: " + row.url + " is this machine"
                                 : "problem: veeam: " + row.url + " is not this machine") != std::string::npos);
}

TEST_CASE("doctor: Veeam's refusal skips the organisations and the clients' Veeam check", "[doctor_command]")
{
    Lab lab;
    lab.http.on(HttpMethod::post, kVeeam + "/v8/token", {make_response(401, "{}")});
    const Run run = lab.run_with_client();
    CHECK_THAT(run.out, ContainsSubstring("problem: veeam error: "));
    CHECK(run.has("skip: veeam: the organisations and their certificates (needs veeam.login)"));
    CHECK(run.has("skip: client 1: Veeam's organisation against the tenant (needs veeam.login)"));
}

TEST_CASE("doctor: a certificate the exporter refuses, and one with no key file", "[doctor_command]")
{
    Lab lab;
    lab.export_failure = rp::CertExportFailure::not_exportable;
    lab.certificate.key_file.reset();
    const Run run = lab.run({});
    CHECK_THAT(run.out, ContainsSubstring("'s private key isn't exportable"));
    CHECK_THAT(run.out, ContainsSubstring("problem: veeam: RestoreProofLab.onmicrosoft.com: no key file of certificate"));
    Lab ace;
    ace.access[ace.certificate.key_file.value()] = 0;
    CHECK_THAT(ace.run({}).out, ContainsSubstring("can't read the key file of certificate " + kThumb +
                                                  " (fix: icacls \"C:\\PD\\Microsoft\\Crypto\\RSA\\MachineKeys\\76c3\" /grant \"*" +
                                                  *rp::doctor::service_sid(rp::kServiceName) + ":(R)\")"));
}

TEST_CASE("doctor: a Graph certificate that won't open", "[doctor_command]")
{
    Lab lab;
    lab.secrets.graph_cert_password = "wrong";
    const Run run = lab.run_with_client();
    CHECK_THAT(run.out, ContainsSubstring("problem: graph: "));
    CHECK(run.has("skip: client 1: graph: the app's token and the three targets (needs graph.certificate)"));
}

TEST_CASE("doctor: a client's profile that can't be read", "[doctor_command]")
{
    Lab lab;
    const std::string missing = utf8(lab.dir.path() / "missing.json");
    CHECK_THAT(lab.run({"--client", missing}).out, ContainsSubstring("problem: client 1: --profile-file "));
    Lab bad;
    CHECK_THAT(bad.run({"--client", "\xff"}).out, ContainsSubstring("problem: client 1: --client "));
}

TEST_CASE("doctor: a client whose organisation Veeam doesn't have, or another tenant's", "[doctor_command]")
{
    Lab lab;
    json profile = Lab::lab_profile();
    profile["veeam_org_name"] = "other.onmicrosoft.com";
    const std::string other = utf8(lab.dir.write("other.json", profile.dump()));
    CHECK_THAT(lab.run({"--client", other}).out,
               ContainsSubstring("problem: client 1: Veeam has no organisation other.onmicrosoft.com (veeam_org_name)"));
    Lab tenant;
    json moved = Lab::lab_profile();
    moved["graph_tenant_id"] = "00000000-0000-4000-8000-000000000009";
    const std::string file = utf8(tenant.dir.write("moved.json", moved.dump()));
    tenant.graph.on(HttpMethod::post,
                    "https://login.microsoftonline.com/00000000-0000-4000-8000-000000000009/oauth2/v2.0/token",
                    {load_fixture("graph", "token-unknown-tenant-400")});
    const Run run = tenant.run({"--client", file});
    CHECK_THAT(run.out, ContainsSubstring("problem: client 1: client_mismatch: "));
    CHECK_THAT(run.out, ContainsSubstring("problem: client 1: graph error: "));
    CHECK(run.has("skip: client 1: graph: the OneDrive RestoreTarget folder (needs client[1].graph.token)"));
}

TEST_CASE("doctor: one role removed from the app's token is one problem line (the Done-when)",
          "[doctor_command]")
{
    Lab lab;
    lab.graph.on(HttpMethod::post, kTokenUrl, {token_with({"Sites.Selected", "Files.SelectedOperations.Selected"})});
    const Run run = lab.run_with_client();
    INFO(run.out << " ERR: " << run.err);
    CHECK(run.exit_code == 5);
    CHECK(count_of(run.out, "problem:") == 1);
    CHECK(run.has_problem("client 1: graph: the app's token lacks Lists.SelectedOperations.Selected"));
    CHECK(run.has("skip: client 1: graph: the RestoreTarget library (needs client[1].graph.role.Lists.SelectedOperations.Selected)"));
}

TEST_CASE("doctor: a target Graph refuses is a problem naming the grant", "[doctor_command]")
{
    Lab lab;
    lab.graph.on(HttpMethod::get, folder_url(), {load_fixture("graph", "onedrive-folder-403-accessdenied")});
    const Run run = lab.run_with_client();
    CHECK_THAT(run.out, ContainsSubstring("problem: client 1: graph error: "));
    CHECK_THAT(run.out, ContainsSubstring("Files.SelectedOperations.Selected"));
}

TEST_CASE("doctor: a --json file that can't be written after the checks is exit 1", "[doctor_command]")
{
    Lab lab;
    const std::filesystem::path file = lab.dir.path() / "late.json";
    lab.on_elevated = [&] { lab.dir.write("late.json", "taken meanwhile"); };
    const Run run = lab.run({"--json", utf8(file)});
    CHECK(run.exit_code == 1);
    CHECK(run.err == "doctor error: --json " + utf8(file) + ": couldn't be written\n");
}

TEST_CASE("doctor: --record writes the exchanges, scrubbed", "[doctor_command]")
{
    Lab lab;
    const std::string folder = utf8(lab.dir.path() / "rec");
    const Run run = lab.run({"--record", folder});
    CHECK_THAT(run.out, ContainsSubstring("recorded "));
    // Every service doctor calls is recorded: Veeam, the Cloud, the TSA and the two hosts.
    CHECK(run.out.find("recorded 0 exchange(s)") == std::string::npos);
    for (const char* service : {"veeam", "cloud", "tsa", "reach"}) {
        CAPTURE(service);
        CHECK(std::filesystem::is_directory(lab.dir.path() / "rec" / service));
    }
    for (const auto& entry : std::filesystem::recursive_directory_iterator(lab.dir.path() / "rec")) {
        if (!entry.is_regular_file()) {
            continue;
        }
        std::ifstream file(entry.path(), std::ios::binary);
        std::ostringstream text;
        text << file.rdbuf();
        CAPTURE(entry.path().string());
        CHECK(text.str().find("Sentinel-Doctor-Veeam-Password") == std::string::npos);
        CHECK(text.str().find("SENTINEL-DOCTOR-ACCESS") == std::string::npos);
    }
}
