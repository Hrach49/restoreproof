// W5.1 (docs/decisions.md 2026-10-15, "W5.1 (#66)", points 2 and 3):
// `rpworker cloud register` and `service start`'s first start, on the Cloud's
// recorded answers (tests/fixtures/cloud/register/), a vault held in memory
// and a temp state folder. Failures first.

#include <rp/cli.hpp>
#include <rp/cloud_api.hpp>
#include <rp/cloud_command.hpp>
#include <rp/config.hpp>
#include <rp/signer.hpp>
#include <rp/vault.hpp>
#include <rp/version.hpp>

#include "fake_http_client.hpp"
#include "restore_command_lab.hpp"
#include "signing_lab.hpp"
#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using rp::HttpMethod;
using rp::HttpResponse;
using rp::test::load_fixture;
using rp::test::load_fixture_json;
using rp::test::to_response;

namespace {

using Args = std::vector<std::string_view>;
const std::string& kUsage = rp::test::restore_command_lab::kUsage;
const std::string kRegisterUrl = "https://cloud.example.invalid/v1/workers/register";
// Tokens of the Cloud's shape, never real ones.
const std::string kInstall = "InstallTok-w51-0123456789abcdefABCDEF_-0123";
const std::string kIssued = "IssuedToke-w51-0123456789abcdefABCDEF_-0123";
// RFC 8032's test key 1: the recorded 201 names its key_id.
const std::string kKeyId = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";
const std::string kWorkerId = "65fddc39-0792-4178-8361-49d53450b29e";
// 2026-10-15T12:40:20Z.
const std::chrono::system_clock::time_point kNow{std::chrono::seconds{1792068020}};

struct Run {
    int code;
    std::string out;
    std::string err;
};

// The recorded 201 with the issued token in the placeholder's place.
HttpResponse registered(const std::string& token = kIssued)
{
    nlohmann::json fixture = load_fixture_json("cloud", "register/201");
    fixture["body"]["api_token"] = token;
    return to_response(fixture);
}

struct Lab {
    rp::test::TempDir dir;
    std::filesystem::path config = dir.write("config.json", rp::test::restore_command_lab::config_values().dump(2));
    std::filesystem::path vault = dir.path() / "vault.bin";
    std::filesystem::path state = dir.path() / "state";
    rp::Secrets secrets;
    // What every write_secrets call wrote, in order.
    std::vector<rp::Secrets> writes;
    // The write (1-based) that throws, or 0 for none.
    int failing_write = 0;
    bool read_fails = false;
    bool worker_file_fails = false;
    std::optional<std::string> host = std::string{"VEEAM-LAB01"};
    rp::test::FakeHttpClient cloud;
    int default_config_calls = 0;
    int default_vault_calls = 0;

    Lab()
    {
        secrets.veeam_username = "rp-veeam";
        secrets.veeam_password = "pw-w51";
        secrets.signing_key_base64 = std::string{rp::test::kSigningKey1Base64};
        secrets.cloud_install_token = kInstall;
        cloud.on(HttpMethod::post, kRegisterUrl, {registered()});
    }

    rp::CloudCommandEnv env()
    {
        rp::CloudCommandEnv env;
        env.default_config_path = [this] {
            ++default_config_calls;
            return config;
        };
        env.default_vault_path = [this] {
            ++default_vault_calls;
            return vault;
        };
        env.default_state_dir = [this] { return state; };
        env.load_secrets = [this](const std::filesystem::path& file) {
            CHECK(file == vault);
            if (read_fails) {
                throw rp::VaultError(file.string() + ": the vault file can't be read");
            }
            return secrets;
        };
        env.write_secrets = [this](const std::filesystem::path& file, const rp::Secrets& next) {
            CHECK(file == vault);
            writes.push_back(next);
            if (static_cast<int>(writes.size()) == failing_write) {
                throw rp::VaultError(file.string() + ": the vault file couldn't be written");
            }
            secrets = next;
        };
        env.make_cloud_http = [this](const rp::Config& loaded) -> std::unique_ptr<rp::IHttpClient> {
            CHECK(loaded.cloud_url == "https://cloud.example.invalid");
            return std::make_unique<rp::test::ForwardingHttpClient>(cloud);
        };
        env.host_name = [this] { return host; };
        env.wall_now = [] { return kNow; };
        if (worker_file_fails) {
            env.write_worker_file = [](const std::filesystem::path&, std::string_view) { return false; };
        }
        return env;
    }

    Run run(Args args)
    {
        std::ostringstream out;
        std::ostringstream err;
        const int code = rp::run_cloud_command(args, out, err, env());
        return {code, out.str(), err.str()};
    }

    // `cloud register --config <config> --vault <vault>` and `more`.
    Run reg(Args more = {})
    {
        const std::string config_arg = config.string();
        const std::string vault_arg = vault.string();
        Args args{"register", "--config", config_arg, "--vault", vault_arg};
        args.insert(args.end(), more.begin(), more.end());
        return run(args);
    }

    std::filesystem::path worker_file() const { return state / "worker.json"; }

    void answer(HttpResponse response) { cloud.on(HttpMethod::post, kRegisterUrl, {std::move(response)}); }
};

// No token of either kind in what the command printed.
void no_token_in(const Run& run)
{
    for (const std::string* token : {&kInstall, &kIssued}) {
        CHECK_THAT(run.out, !ContainsSubstring(*token));
        CHECK_THAT(run.err, !ContainsSubstring(*token));
    }
}

const std::string kNoRequest = "";

} // namespace

TEST_CASE("cloud: a command line it doesn't take is usage, nothing read or sent", "[cloud_command]")
{
    const Args args = GENERATE(Args{}, Args{"Register"}, Args{"unregister"}, Args{"register", "extra"},
                               Args{"register", "--name"}, Args{"register", "--name", ""},
                               Args{"register", "--config", "a", "--config", "b"},
                               Args{"register", "--outbox", "x"}, Args{"register", "--vault"});
    CAPTURE(args);
    Lab lab;

    const Run run = lab.run(args);
    CHECK(run.code == rp::exit_code::usage);
    CHECK(run.out.empty());
    CHECK(run.err == kUsage);
    CHECK(lab.cloud.requests().empty());
    CHECK(lab.default_config_calls == 0);
}

TEST_CASE("cloud register: a vault that already holds the API token registers nothing",
          "[cloud_command]")
{
    Lab lab;
    lab.secrets.cloud_api_token = kIssued;

    const Run run = lab.reg();
    CHECK(run.code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "cloud register: already registered (cloud_api_token is in the vault); nothing "
                     "was done\n");
    CHECK(lab.cloud.requests().empty());
    CHECK(lab.writes.empty());
    no_token_in(run);
}

TEST_CASE("cloud register: without an install token, a signing key or a readable vault nothing is sent",
          "[cloud_command]")
{
    SECTION("no install token")
    {
        Lab lab;
        lab.secrets.cloud_install_token.reset();
        const Run run = lab.reg();
        CHECK(run.code == rp::exit_code::config);
        CHECK(run.err == "config error: cloud_install_token is not in the vault\n");
        CHECK(lab.cloud.requests().empty());
        CHECK(lab.writes.empty());
    }
    SECTION("an empty install token")
    {
        Lab lab;
        lab.secrets.cloud_install_token = "";
        const Run run = lab.reg();
        CHECK(run.err == "config error: cloud_install_token is not in the vault\n");
        CHECK(lab.cloud.requests().empty());
    }
    SECTION("no signing key")
    {
        Lab lab;
        lab.secrets.signing_key_base64.reset();
        const Run run = lab.reg();
        CHECK(run.code == rp::exit_code::config);
        CHECK(run.err == "config error: signing_key_base64 is not in the vault\n");
        CHECK(lab.cloud.requests().empty());
    }
    SECTION("a signing key that is none")
    {
        Lab lab;
        lab.secrets.signing_key_base64 = "not a key";
        const Run run = lab.reg();
        CHECK(run.code == rp::exit_code::config);
        CHECK(run.err ==
              "config error: signing_key_base64 is not an Ed25519 private key (Base64 of PKCS#8 DER)\n");
        CHECK(lab.cloud.requests().empty());
    }
    SECTION("a vault that can't be read")
    {
        Lab lab;
        lab.read_fails = true;
        const Run run = lab.reg();
        CHECK(run.code == rp::exit_code::config);
        CHECK(run.err == "config error: " + lab.vault.string() + ": the vault file can't be read\n");
        CHECK(lab.cloud.requests().empty());
    }
    SECTION("a config that doesn't load")
    {
        Lab lab;
        lab.config = lab.dir.write("bad.json", "{}");
        const Run run = lab.reg();
        CHECK(run.code == rp::exit_code::config);
        CHECK_THAT(run.err, Catch::Matchers::StartsWith("config error: "));
        CHECK(lab.cloud.requests().empty());
    }
}

TEST_CASE("cloud register: a name the Cloud wouldn't take is refused before anything is sent",
          "[cloud_command]")
{
    SECTION("--name")
    {
        Lab lab;
        const Run run = lab.reg({"--name", "a\tb"});
        CHECK(run.code == rp::exit_code::usage);
        CHECK(run.err == "usage error: --name must be 1 to 128 characters with no control character\n");
        CHECK(lab.cloud.requests().empty());
        CHECK(lab.writes.empty());
    }
    SECTION("this machine's name")
    {
        Lab lab;
        lab.host = GENERATE(std::optional<std::string>{}, std::optional<std::string>{std::string(129, 'n')});
        const Run run = lab.reg();
        CHECK(run.code == rp::exit_code::config);
        CHECK(run.err == "config error: this machine's name can't be the Worker's name; give --name\n");
        CHECK(lab.cloud.requests().empty());
    }
}

TEST_CASE("cloud register: a vault this account can't write is found before the install token is spent",
          "[cloud_command]")
{
    Lab lab;
    lab.failing_write = 1;

    const Run run = lab.reg();
    CHECK(run.code == rp::exit_code::config);
    CHECK(run.err == "vault error: " + lab.vault.string() + ": the vault file couldn't be written\n");
    CHECK(lab.cloud.requests().empty());
    // The one write tried was the vault as it was.
    REQUIRE(lab.writes.size() == 1);
    CHECK(lab.writes[0].cloud_install_token == kInstall);
    CHECK_FALSE(lab.writes[0].cloud_api_token);
}

TEST_CASE("cloud register: each refusal of the Cloud is its line and code, the install token kept",
          "[cloud_command]")
{
    const auto [fixture, code, line] = GENERATE(table<std::string, int, std::string>({
        {"register/401", rp::exit_code::auth,
         "cloud register: the install token was refused (unknown, used or expired); make a new one "
         "(manage.py create-worker-token)"},
        {"register/401-used", rp::exit_code::auth,
         "cloud register: the install token was refused (unknown, used or expired); make a new one "
         "(manage.py create-worker-token)"},
        {"register/400", rp::exit_code::service, "cloud register: the Cloud refused this Worker's public key"},
        {"register/409", rp::exit_code::service, "cloud register: this Worker's key is already registered"},
        {"register/422-body", rp::exit_code::service, "cloud register: refused (http_422)"},
        {"jobs/502-proxy", rp::exit_code::transient,
         "cloud register: the Cloud couldn't be reached (http_502); run it again"},
    }));
    CAPTURE(fixture);
    Lab lab;
    lab.answer(load_fixture("cloud", fixture));

    const Run run = lab.reg();
    CHECK(run.code == code);
    CHECK(run.out.empty());
    CHECK(run.err == line + "\n");
    // Only the check write: the vault is as it was.
    REQUIRE(lab.writes.size() == 1);
    CHECK(lab.secrets.cloud_install_token == kInstall);
    CHECK_FALSE(lab.secrets.cloud_api_token);
    CHECK_FALSE(std::filesystem::exists(lab.worker_file()));
    no_token_in(run);
}

TEST_CASE("cloud register: another status is a refusal; a 5xx is the Cloud not reached", "[cloud_command]")
{
    const auto [status, code, line] = GENERATE(table<int, int, std::string>({
        {413, rp::exit_code::service, "cloud register: refused (http_413)"},
        {404, rp::exit_code::service, "cloud register: refused (http_404)"},
        {200, rp::exit_code::service, "cloud register: refused (http_200)"},
        {302, rp::exit_code::service, "cloud register: refused (http_302)"},
        {500, rp::exit_code::transient, "cloud register: the Cloud couldn't be reached (http_500); run it again"},
        {503, rp::exit_code::transient, "cloud register: the Cloud couldn't be reached (http_503); run it again"},
        {1000, rp::exit_code::transient, "cloud register: the Cloud couldn't be reached (internal); run it again"},
    }));
    CAPTURE(status);
    Lab lab;
    lab.answer(rp::test::make_response(status, ""));

    const Run run = lab.reg();
    CHECK(run.code == code);
    CHECK(run.err == line + "\n");
    CHECK(lab.secrets.cloud_install_token == kInstall);
}

TEST_CASE("cloud register: a request that got no answer leaves the install token for another try",
          "[cloud_command]")
{
    const auto [error, word] = GENERATE(table<rp::TransportError, std::string>({
        {rp::TransportError::timeout, "timeout"},
        {rp::TransportError::connect, "unreachable"},
        {rp::TransportError::dropped, "unreachable"},
        {rp::TransportError::handshake, "unreachable"},
        {rp::TransportError::tls, "unreachable"},
        {rp::TransportError::other, "internal"},
    }));
    Lab lab;
    lab.cloud.on(HttpMethod::post, kRegisterUrl, [error](const rp::HttpRequest&) -> HttpResponse {
        throw rp::HttpError("test", error, 0, 1);
    });

    const Run run = lab.reg();
    CHECK(run.code == rp::exit_code::transient);
    CHECK(run.err == "cloud register: the Cloud couldn't be reached (" + word + "); run it again\n");
    CHECK(lab.secrets.cloud_install_token == kInstall);
}

TEST_CASE("cloud register: a client that throws a status has that status's line", "[cloud_command]")
{
    Lab lab;
    lab.cloud.on(HttpMethod::post, kRegisterUrl, [](const rp::HttpRequest&) -> HttpResponse {
        throw rp::HttpError("test", rp::TransportError::none, 503, 1);
    });
    CHECK(lab.reg().err == "cloud register: the Cloud couldn't be reached (http_503); run it again\n");

    Lab other;
    other.cloud.on(HttpMethod::post, kRegisterUrl,
                   [](const rp::HttpRequest&) -> HttpResponse { throw std::runtime_error("no"); });
    CHECK(other.reg().err == "cloud register: the Cloud couldn't be reached (internal); run it again\n");
}

TEST_CASE("cloud register: a 201 that isn't the Cloud's, or isn't this Worker's, stores nothing",
          "[cloud_command]")
{
    SECTION("no contract header")
    {
        Lab lab;
        HttpResponse answer = registered();
        answer.headers.erase("X-Restoreproof-Api");
        lab.answer(answer);
        const Run run = lab.reg();
        CHECK(run.code == rp::exit_code::service);
        CHECK(run.err ==
              "cloud register: the answer is not a RestoreProof Cloud's (no X-RestoreProof-API: 1)\n");
        CHECK_FALSE(lab.secrets.cloud_api_token);
        CHECK(lab.secrets.cloud_install_token == kInstall);
        no_token_in(run);
    }
    SECTION("another contract")
    {
        Lab lab;
        HttpResponse answer = registered();
        answer.headers["X-Restoreproof-Api"] = "2";
        lab.answer(answer);
        const Run run = lab.reg();
        CHECK(run.code == rp::exit_code::service);
        CHECK(run.err == "cloud register: the answer is not a RestoreProof Cloud's (X-RestoreProof-API: 2)\n");
        CHECK_FALSE(lab.secrets.cloud_api_token);
    }
    SECTION("a body that isn't the answer, or another key's")
    {
        Lab lab;
        nlohmann::json fixture = load_fixture_json("cloud", "register/201");
        fixture["body"]["api_token"] = kIssued;
        const bool other_key = GENERATE(true, false);
        if (other_key) {
            fixture["body"]["key_id"] = std::string(64, 'a');
        } else {
            fixture["body"]["api_token"] = "SCRUBBED";
        }
        lab.answer(to_response(fixture));
        const Run run = lab.reg();
        CHECK(run.code == rp::exit_code::service);
        CHECK(run.err == "cloud register: the Cloud's answer is not this Worker's registration\n");
        CHECK_FALSE(lab.secrets.cloud_api_token);
        CHECK(lab.secrets.cloud_install_token == kInstall);
        no_token_in(run);
    }
}

TEST_CASE("cloud register: the Cloud's 201 stores the API token and removes the install token in one write",
          "[cloud_command]")
{
    Lab lab;

    const Run run = lab.reg();
    CHECK(run.code == rp::exit_code::ok);
    CHECK(run.out == "registered worker " + kWorkerId + " key " + kKeyId + "\n");
    CHECK(run.err.empty());
    no_token_in(run);

    // The check write, then the one that matters.
    REQUIRE(lab.writes.size() == 2);
    CHECK(lab.writes[0].cloud_install_token == kInstall);
    CHECK(lab.writes[1].cloud_api_token == kIssued);
    CHECK_FALSE(lab.writes[1].cloud_install_token);
    CHECK(lab.writes[1].signing_key_base64 == std::string{rp::test::kSigningKey1Base64});
    CHECK(lab.writes[1].veeam_password == "pw-w51");

    // The one request, as point 2 has it.
    const std::vector<rp::HttpRequest> sent = lab.cloud.requests();
    REQUIRE(sent.size() == 1);
    const rp::HttpRequest& request = sent[0];
    CHECK(request.method == HttpMethod::post);
    CHECK(request.url == kRegisterUrl);
    CHECK(request.content_type == "application/json");
    CHECK(request.max_attempts == 1);
    CHECK_FALSE(request.retry_on_status);
    CHECK(request.timeout == rp::kRegisterTimeout);
    CHECK(request.max_body_bytes == rp::kMaxRegisterAnswerBytes);
    CHECK(request.headers.empty());
    CHECK(request.body == rp::registration_body(kInstall, rp::test::signing_key().public_key_pem(),
                                                "VEEAM-LAB01", rp::version()));

    // state\worker.json, no token in it.
    std::ifstream file(lab.worker_file(), std::ios::binary);
    const std::string text{std::istreambuf_iterator<char>(file), {}};
    CHECK(text == rp::worker_record_text({kWorkerId, kKeyId, "https://cloud.example.invalid",
                                          "2026-10-15T12:40:20Z"}));
    CHECK_THAT(text, !ContainsSubstring(kIssued));
}

TEST_CASE("cloud register: --name is the name sent", "[cloud_command]")
{
    Lab lab;
    lab.host.reset();

    CHECK(lab.reg({"--name", "veeam-01.contoso.local"}).code == rp::exit_code::ok);
    const nlohmann::json body = nlohmann::json::parse(lab.cloud.requests().at(0).body);
    CHECK(body["worker_name"] == "veeam-01.contoso.local");
}

TEST_CASE("cloud register: without --config and --vault the defaults are read", "[cloud_command]")
{
    Lab lab;
    std::ostringstream out;
    std::ostringstream err;
    const Args args{"register"};

    CHECK(rp::run_cloud_command(args, out, err, lab.env()) == rp::exit_code::ok);
    CHECK(lab.default_config_calls == 1);
    CHECK(lab.default_vault_calls == 1);
}

TEST_CASE("cloud register: a vault that can't take the token after the 201 says what to do", "[cloud_command]")
{
    Lab lab;
    lab.failing_write = 2;

    const Run run = lab.reg();
    CHECK(run.code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "cloud register: registered as worker " + kWorkerId +
                         ", but the API token couldn't be stored; revoke that Worker (manage.py "
                         "revoke-worker) and register again with a new signing key and a new install "
                         "token\n");
    CHECK_FALSE(std::filesystem::exists(lab.worker_file()));
    no_token_in(run);
}

TEST_CASE("cloud register: a worker.json that can't be written leaves the registration", "[cloud_command]")
{
    Lab lab;
    lab.worker_file_fails = true;

    const Run run = lab.reg();
    CHECK(run.code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "cloud register: registered as worker " + kWorkerId +
                         "; state\\worker.json couldn't be written\n");
    CHECK(lab.secrets.cloud_api_token == kIssued);
}

TEST_CASE("cloud register: the real writer makes the state folder and replaces a worker.json",
          "[cloud_command]")
{
    Lab lab;
    std::filesystem::create_directories(lab.state);
    lab.dir.write("state/worker.json", "old");

    CHECK(lab.reg().code == rp::exit_code::ok);
    CHECK(rp::parse_worker_record([&] {
        std::ifstream file(lab.worker_file(), std::ios::binary);
        return std::string{std::istreambuf_iterator<char>(file), {}};
    }()));
}

TEST_CASE("cloud register --record writes the exchange with no token", "[cloud_command]")
{
    Lab lab;
    const std::filesystem::path recording = lab.dir.path() / "rec";
    const std::string recording_arg = recording.string();

    const Run run = lab.reg({"--record", recording_arg});
    CHECK(run.code == rp::exit_code::ok);
    CHECK(run.out == "registered worker " + kWorkerId + " key " + kKeyId + "\nrecorded 1 exchange(s) in " +
                         recording_arg + "\n");
    std::size_t files = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(recording)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        ++files;
        std::ifstream file(entry.path(), std::ios::binary);
        const std::string text{std::istreambuf_iterator<char>(file), {}};
        CHECK_THAT(text, !ContainsSubstring(kIssued));
        CHECK_THAT(text, !ContainsSubstring(kInstall));
        CHECK_THAT(text, ContainsSubstring("X-RestoreProof-API"));
        CHECK(entry.path().parent_path().filename() == "cloud");
    }
    CHECK(files == 1);
}

TEST_CASE("first start: nothing to do with an API token or without an install token", "[cloud_command]")
{
    Lab lab;
    const bool has_api = GENERATE(true, false);
    if (has_api) {
        lab.secrets.cloud_api_token = kIssued;
    } else {
        lab.secrets.cloud_install_token.reset();
    }
    std::ostringstream out;
    std::ostringstream err;

    CHECK(rp::first_start(lab.config, lab.vault, out, err, lab.env()) == rp::exit_code::ok);
    CHECK(out.str().empty());
    CHECK(err.str().empty());
    CHECK(lab.cloud.requests().empty());
    CHECK(lab.writes.empty());
}

TEST_CASE("first start: an install token without an API token registers", "[cloud_command]")
{
    Lab lab;
    std::ostringstream out;
    std::ostringstream err;

    CHECK(rp::first_start(lab.config, lab.vault, out, err, lab.env()) == rp::exit_code::ok);
    CHECK(out.str() == "registered worker " + kWorkerId + " key " + kKeyId + "\n");
    CHECK(lab.secrets.cloud_api_token == kIssued);

    Lab refused;
    refused.answer(load_fixture("cloud", "register/401"));
    std::ostringstream out2;
    std::ostringstream err2;
    CHECK(rp::first_start(refused.config, refused.vault, out2, err2, refused.env()) == rp::exit_code::auth);
}

TEST_CASE("first start: a vault that can't be read is a config error", "[cloud_command]")
{
    Lab lab;
    lab.read_fails = true;
    std::ostringstream out;
    std::ostringstream err;

    CHECK(rp::first_start(lab.config, lab.vault, out, err, lab.env()) == rp::exit_code::config);
    CHECK(err.str() == "config error: " + lab.vault.string() + ": the vault file can't be read\n");
}

TEST_CASE("the cloud command's real environment is the defaults", "[cloud_command]")
{
    const rp::CloudCommandEnv env = rp::default_cloud_command_env();
    CHECK_FALSE(env.default_config_path);
    CHECK_FALSE(env.default_vault_path);
    CHECK_FALSE(env.default_state_dir);
    CHECK_FALSE(env.load_config);
    CHECK_FALSE(env.load_secrets);
    CHECK_FALSE(env.write_secrets);
    CHECK_FALSE(env.make_cloud_http);
    CHECK_FALSE(env.host_name);
    CHECK_FALSE(env.wall_now);
    CHECK_FALSE(env.write_worker_file);
}
