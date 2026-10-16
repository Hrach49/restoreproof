#include <rp/cloud_command.hpp>

#include <rp/cert_export.hpp>
#include <rp/cli.hpp>
#include <rp/cloud_api.hpp>
#include <rp/outbox.hpp>
#include <rp/signer.hpp>
#include <rp/uploader.hpp>
#include <rp/vault.hpp>
#include <rp/version.hpp>

#include "atomic_file.hpp"
#include "command_config.hpp"
#include "host_name.hpp"
#include "http_exchange.hpp"

#include <format>
#include <ostream>
#include <system_error>

namespace rp {

namespace {

constexpr std::string_view kRegister = "register";

// Wipes the string it names when it goes.
struct Wiped {
    std::string& text;
    ~Wiped() { secure_wipe(text); }
};

// The ConfigError `step` throws, as its message; nullopt when it ran. One
// return after the handler (see signer.cpp): each refusal is decided outside it.
template <typename Step> std::optional<std::string> config_problem(Step&& step)
{
    std::optional<std::string> problem;
    try {
        step();
    } catch (const ConfigError& e) {
        problem = e.what();
    }
    return problem;
}

bool is_set(const std::optional<std::string>& secret) noexcept
{
    return secret && !secret->empty();
}

Secrets read_secrets(const std::filesystem::path& vault, const CloudCommandEnv& env)
{
    return env.load_secrets ? env.load_secrets(vault) : read_vault(vault);
}

void write_secrets(const std::filesystem::path& vault, const Secrets& secrets,
                   const CloudCommandEnv& env)
{
    return env.write_secrets ? env.write_secrets(vault, secrets) : write_vault(vault, secrets);
}

bool write_worker_file(const std::filesystem::path& file, std::string_view text,
                       const CloudCommandEnv& env)
{
    if (env.write_worker_file) {
        return env.write_worker_file(file, text);
    }
    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    return write_file_atomically(file, text, AtomicWriteOptions{.replace = true});
}

// "http_<status>".
std::string status_word(int status)
{
    return std::format("http_{}", status);
}

// The line and code for a status that isn't the 201 (point 2).
int refused(int status, std::ostream& err)
{
    if (status == 401) {
        err << "cloud register: the install token was refused (unknown, used or expired); make a "
               "new one (manage.py create-worker-token)\n";
        return exit_code::auth;
    }
    if (status == 400) {
        err << "cloud register: the Cloud refused this Worker's public key\n";
        return exit_code::service;
    }
    if (status == 409) {
        err << "cloud register: this Worker's key is already registered\n";
        return exit_code::service;
    }
    if (status >= 500) {
        err << "cloud register: the Cloud couldn't be reached (" << status_word(status)
            << "); run it again\n";
        return exit_code::transient;
    }
    err << "cloud register: refused (" << status_word(status) << ")\n";
    return exit_code::service;
}

// The 201 (point 2): stored, or why not.
int store(const HttpResponse& answer, const Config& config, const std::string& key_id,
          WipedSecrets& held, const std::filesystem::path& vault, std::ostream& out,
          std::ostream& err, const CloudCommandEnv& env)
{
    const CloudAnswerKind kind = cloud_answer_kind(answer);
    if (kind != CloudAnswerKind::cloud) {
        err << "cloud register: the answer is not a RestoreProof Cloud's ("
            << (kind == CloudAnswerKind::not_cloud
                    ? std::string{"no X-RestoreProof-API: 1"}
                    : std::string{kCloudApiHeader} + ": " + other_contract_text(answer))
            << ")\n";
        return exit_code::service;
    }
    std::optional<Registration> registration = parse_registration(answer.body);
    if (!registration || registration->key_id != key_id) {
        err << "cloud register: the Cloud's answer is not this Worker's registration\n";
        return exit_code::service;
    }
    Wiped token{registration->api_token};
    secure_wipe(*held.secrets.cloud_install_token);
    held.secrets.cloud_install_token.reset();
    held.secrets.cloud_api_token = registration->api_token;
    if (config_problem([&] { write_secrets(vault, held.secrets, env); })) {
        err << "cloud register: registered as worker " << registration->worker_id
            << ", but the API token couldn't be stored; revoke that Worker (manage.py "
               "revoke-worker) and register again with a new signing key and a new install "
               "token\n";
        return exit_code::config;
    }
    const WorkerRecord record{registration->worker_id, registration->key_id, config.cloud_url,
                              outbox_time_text(env.wall_now ? env.wall_now()
                                                            : std::chrono::system_clock::now())};
    const std::filesystem::path state =
        env.default_state_dir ? env.default_state_dir() : default_state_dir();
    if (!write_worker_file(state / std::string{kWorkerFileName}, worker_record_text(record), env)) {
        err << "cloud register: registered as worker " << registration->worker_id
            << "; state\\worker.json couldn't be written\n";
        return exit_code::config;
    }
    out << "registered worker " << registration->worker_id << " key " << registration->key_id
        << '\n';
    return exit_code::ok;
}

// The install token there, and the signing key's public half and key id.
// Throws ConfigError naming the secret that is missing or no key.
void take_key(const Secrets& secrets, std::string& pem, std::string& key_id)
{
    if (!is_set(secrets.cloud_install_token)) {
        throw ConfigError(std::string{kNameCloudInstallToken}, not_in_vault(kNameCloudInstallToken));
    }
    if (!is_set(secrets.signing_key_base64)) {
        throw ConfigError(std::string{kNameSigningKeyBase64}, not_in_vault(kNameSigningKeyBase64));
    }
    const std::optional<SigningKey> key = SigningKey::from_base64(*secrets.signing_key_base64);
    if (!key) {
        throw ConfigError(std::string{kNameSigningKeyBase64},
                          std::string{kNameSigningKeyBase64} +
                              " is not an Ed25519 private key (Base64 of PKCS#8 DER)");
    }
    pem = key->public_key_pem();
    key_id = key->key_id();
}

// --name (held to its rule by the caller), else this machine's name. Throws
// ConfigError for a machine's name the Cloud wouldn't take.
std::string worker_name(const RegisterRequest& request, const CloudCommandEnv& env)
{
    if (request.name) {
        return *request.name;
    }
    const std::optional<std::string> host = env.host_name ? env.host_name() : dns_host_name();
    if (!host || !is_worker_name(*host)) {
        throw ConfigError("name", "this machine's name can't be the Worker's name; give --name");
    }
    return *host;
}

} // namespace

CloudCommandEnv default_cloud_command_env()
{
    return {};
}

int register_worker(const RegisterRequest& request, std::ostream& out, std::ostream& err,
                    const CloudCommandEnv& env)
{
    Config config;
    WipedSecrets held;
    std::shared_ptr<FixtureRecorder> recorder;
    std::string key_id;
    std::string pem;
    std::string name;
    std::optional<std::string> problem = config_problem([&] {
        config = env.load_config ? env.load_config(request.config) : load_config(request.config);
        held.secrets = read_secrets(request.vault, env);
    });
    if (!problem && is_set(held.secrets.cloud_api_token)) {
        err << "cloud register: already registered (cloud_api_token is in the vault); nothing "
               "was done\n";
        return exit_code::config;
    }
    if (!problem) {
        problem = config_problem([&] { take_key(held.secrets, pem, key_id); });
    }
    if (!problem && request.name && !is_worker_name(*request.name)) {
        err << "usage error: --name must be 1 to 128 characters with no control character\n";
        return exit_code::usage;
    }
    if (!problem) {
        problem = config_problem([&] { name = worker_name(request, env); });
    }
    if (problem) {
        err << "config error: " << *problem << '\n';
        return exit_code::config;
    }
    // The vault as it is, written back before the token is spent: a vault this
    // account can't write is found while it can still be used.
    if (const std::optional<std::string> unwritten =
            config_problem([&] { write_secrets(request.vault, held.secrets, env); })) {
        err << "vault error: " << *unwritten << '\n';
        return exit_code::config;
    }
    if (const std::optional<std::string> refused_record = config_problem(
            [&] { recorder = open_recording(request.record, "cloud register", held.secrets); })) {
        err << "config error: " << *refused_record << '\n';
        return exit_code::config;
    }
    const std::unique_ptr<IHttpClient> http = recorded(
        env.make_cloud_http ? env.make_cloud_http(config) : make_cloud_http_client(config), recorder,
        "cloud");

    HttpRequest post;
    post.method = HttpMethod::post;
    post.url = cloud_endpoint(config.cloud_url, kRegisterPath);
    post.body = registration_body(*held.secrets.cloud_install_token, pem, name, version());
    Wiped body{post.body};
    post.content_type = "application/json";
    post.timeout = kRegisterTimeout;
    post.retry_on_status = false;
    post.max_attempts = 1;
    post.max_body_bytes = kMaxRegisterAnswerBytes;
    Exchange answer = exchange(*http, post);
    int code = exit_code::transient;
    if (!answer.response) {
        err << "cloud register: the Cloud couldn't be reached (" << answer.word << "); run it again\n";
    } else {
        Wiped answer_body{answer.response->body};
        code = answer.response->status == 201
                   ? store(*answer.response, config, key_id, held, request.vault, out, err, env)
                   : refused(answer.response->status, err);
    }
    return finish_recording(recorder.get(), out, err, code);
}

int first_start(const std::filesystem::path& config, const std::filesystem::path& vault,
                std::ostream& out, std::ostream& err, const CloudCommandEnv& env)
{
    WipedSecrets held;
    if (const std::optional<std::string> problem =
            config_problem([&] { held.secrets = read_secrets(vault, env); })) {
        err << "config error: " << *problem << '\n';
        return exit_code::config;
    }
    if (is_set(held.secrets.cloud_api_token) || !is_set(held.secrets.cloud_install_token)) {
        return exit_code::ok;
    }
    return register_worker({config, vault, std::nullopt, std::nullopt}, out, err, env);
}

int run_cloud_command(std::span<const std::string_view> args, std::ostream& out,
                      std::ostream& err, const CloudCommandEnv& env)
{
    std::optional<CommandOptions> options;
    if (!args.empty() && args[0] == kRegister) {
        options = parse_options(args.subspan(1), {"--config", "--vault", "--name", "--record"});
    }
    const bool empty_value =
        options && std::ranges::any_of(options->values, [](const auto& v) { return v.second.empty(); });
    if (!options || empty_value) {
        err << kCliUsage;
        return exit_code::usage;
    }
    RegisterRequest request;
    if (const std::optional<std::string> problem = config_problem([&] {
            request.config = command_config_path(
                options->value("--config"),
                env.default_config_path ? env.default_config_path : default_config_path);
            request.vault = command_vault_path(
                options->value("--vault"),
                env.default_vault_path ? env.default_vault_path : default_vault_path);
        })) {
        err << "config error: " << *problem << '\n';
        return exit_code::config;
    }
    if (const std::optional<std::string_view> name = options->value("--name")) {
        request.name = std::string{*name};
    }
    request.record = options->value("--record");
    return register_worker(request, out, err, env);
}

} // namespace rp
