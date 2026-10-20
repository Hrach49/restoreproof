#pragma once

// `rpworker cloud register` (W5.1, docs/decisions.md 2026-10-15, "W5.1
// (#66)", points 2 and 3) and `rpworker cloud revoke` (W7.3): the Worker's
// first start and its last word to the Cloud. Registration: The install token the
// operator put in the vault (`rpworker vault set cloud_install_token`) is
// sent once with the signing key's public half to POST
// <cloud_url>/v1/workers/register; the API token the Cloud answers with goes
// into the vault in the same write that removes the install token, and
// state\worker.json records the registration. The vault is written only at
// the operator's console, never by the service, whose account reads it
// alone: `rpworker service start` runs this when the vault has no API token
// (rp::first_start).
//
// Neither token reaches `out`, `err`, a log line, worker.json or a
// recording.
//
// Strict (100% line), by its name.

#include <rp/config.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace rp {

// The registration's one request: connect, send and the answer.
inline constexpr std::chrono::milliseconds kRegisterTimeout{30000};
// The most that is read of its answer.
inline constexpr std::uint64_t kMaxRegisterAnswerBytes = 64u * 1024u;

// What the command reaches outside itself; each null = the real one.
struct CloudCommandEnv {
    // Without --config: rp::default_config_path. Called only then.
    std::function<std::filesystem::path()> default_config_path;
    // Without --vault: rp::default_vault_path. Called only then.
    std::function<std::filesystem::path()> default_vault_path;
    // Where worker.json goes: rp::default_state_dir.
    std::function<std::filesystem::path()> default_state_dir;
    // rp::load_config.
    std::function<Config(const std::filesystem::path&)> load_config;
    // rp::read_vault and rp::write_vault.
    std::function<Secrets(const std::filesystem::path&)> load_secrets;
    std::function<void(const std::filesystem::path&, const Secrets&)> write_secrets;
    // rp::make_cloud_http_client (rp/uploader.hpp). With --record its
    // exchanges go under "cloud".
    std::function<std::unique_ptr<IHttpClient>(const Config&)> make_cloud_http;
    // This machine's DNS host name in UTF-8, or nullopt when Windows can't
    // say: GetComputerNameExW(ComputerNameDnsHostname).
    std::function<std::optional<std::string>()> host_name;
    // The wall clock worker.json's registered_at takes.
    std::function<std::chrono::system_clock::time_point()> wall_now;
    // Writes worker.json whole, over one that is there, making its folder
    // first; whether it did. Null: the atomic writer (replace) after
    // create_directories.
    std::function<bool(const std::filesystem::path&, std::string_view)> write_worker_file;
};

// The real environment: every member null.
CloudCommandEnv default_cloud_command_env();

// What one registration is given.
struct RegisterRequest {
    std::filesystem::path config;
    std::filesystem::path vault;
    // --name; nullopt: env.host_name().
    std::optional<std::string> name;
    // --record <dir>.
    std::optional<std::string_view> record;
};

// One registration, in point 2's order: the config; the vault read; an API
// token there ("cloud register: already registered (cloud_api_token is in
// the vault); nothing was done", 1); no install token ("config error:
// cloud_install_token is not in the vault", 1); the signing key ("config
// error: signing_key_base64 is not in the vault" or "... is not an Ed25519
// private key (Base64 of PKCS#8 DER)", 1); the name ("usage error: --name
// must be 1 to 128 characters with no control character", 64, or "config
// error: this machine's name can't be the Worker's name; give --name", 1);
// the vault written back unchanged ("vault error: <what()>", 1); then the
// request. The answers:
//   201 with the contract header and this key's key_id: the vault written
//       once (cloud_api_token set, cloud_install_token removed), then
//       worker.json; "registered worker <id> key <key_id>" on `out`, 0;
//   201 without the header: "cloud register: the answer is not a RestoreProof
//       Cloud's (no X-RestoreProof-API: 1)", 4; with another value the same
//       line, "(X-RestoreProof-API: <text>)";
//   201 whose body isn't the answer or names another key: "cloud register:
//       the Cloud's answer is not this Worker's registration", 4;
//   401: "cloud register: the install token was refused (unknown, used or
//       expired); make a new one (manage.py create-worker-token)", 2;
//   400: "cloud register: the Cloud refused this Worker's public key", 4;
//   409: "cloud register: this Worker's key is already registered", 4;
//   5xx, a timeout, no connection, a TLS failure: "cloud register: the Cloud
//       couldn't be reached (<word>); run it again", 3, <word> http_<status>,
//       timeout, unreachable or internal;
//   any other status: "cloud register: refused (http_<status>)", 4.
// A vault that can't be written after the 201: "cloud register: registered as
// worker <id>, but the API token couldn't be stored; revoke that Worker
// (manage.py revoke-worker) and register again with a new signing key and a
// new install token", 1. worker.json not written: "cloud register: registered
// as worker <id>; state\worker.json couldn't be written", 1. A ConfigError
// before the request is "config error: <what()>", 1.
int register_worker(const RegisterRequest& request, std::ostream& out, std::ostream& err,
                    const CloudCommandEnv& env);

// `rpworker service start`'s first start (point 2): with an API token in the
// vault, or without an install token, nothing (0, no line); else
// register_worker's answer. A vault that can't be read is "config error:
// <what()>", 1.
int first_start(const std::filesystem::path& config, const std::filesystem::path& vault,
                std::ostream& out, std::ostream& err, const CloudCommandEnv& env);

// What one revoke is given (W7.3).
struct RevokeRequest {
    std::filesystem::path config;
    std::filesystem::path vault;
    // --record <dir>.
    std::optional<std::string_view> record;
};

// `rpworker cloud revoke` (W7.3, docs/decisions.md 2026-10-19, "W7.3 (#82)
// and W7.4 (#83)", point 5): the uninstall's call. The config; the vault read;
// no API token ("config error: cloud_api_token is not in the vault; this
// Worker is not registered", 1); state\worker.json, when it reads, naming
// another cloud_url than the config's: "cloud revoke: this Worker is
// registered with <its url> (state\worker.json) and the config's cloud_url
// is <url>; nothing was sent: ...", 1 (the token is that Cloud's, and another
// Cloud's 401 would remove it); the vault written back unchanged ("vault
// error: <what()>", 1); the recording opened; then one POST to
// <cloud_url>/v1/workers/self/revoke with the token as the bearer and no
// body. The answers:
//   a 2xx with the contract header: the token removed from the vault in one
//       write; "revoked worker <id>" on `out` (the id from state\worker.json
//       when it reads, else "revoked this Worker"), 0; worker.json is left;
//   a 2xx without the header: "cloud revoke: the answer is not a RestoreProof
//       Cloud's (no X-RestoreProof-API: 1)", 4 (with another value "(X-
//       RestoreProof-API: <text>)"); nothing removed;
//   401 with the contract header: "cloud revoke: the Cloud doesn't know this
//       token (revoked already, or never this Cloud's); it was removed from
//       the vault", the token removed, 2;
//   401 without it (a proxy's, a captive page's): "cloud revoke: the answer is
//       not a RestoreProof Cloud's (no X-RestoreProof-API: 1 on its 401); the
//       token is kept", 4;
//   5xx, a timeout, no connection, a TLS failure: "cloud revoke: the Cloud
//       couldn't be reached (<word>); run it again, or revoke the Worker in
//       the Cloud (manage.py revoke-worker)", 3, the token kept;
//   any other status: "cloud revoke: refused (http_<status>)", 4, kept.
// A vault that can't take the removal after the 2xx: "cloud revoke: the Cloud
// revoked this Worker, but the API token couldn't be removed from the vault
// (rpworker vault remove cloud_api_token)", 1; after the 401 the 401's line
// ending "; it couldn't be removed from the vault (rpworker vault remove
// cloud_api_token)", 1. The token reaches no stream, log line or recording.
int revoke_worker(const RevokeRequest& request, std::ostream& out, std::ostream& err,
                  const CloudCommandEnv& env);

// `rpworker cloud ...`. `args` is what follows "cloud", in UTF-8: `register
// [--config <path>] [--vault <file>] [--name <worker name>] [--record <dir>]`
// or `revoke [--config <path>] [--vault <file>] [--record <dir>]`.
// 64 with rp::kCliUsage on `err` for anything else (no subcommand, an unknown
// one, an option twice, without its value or with an empty one).
int run_cloud_command(std::span<const std::string_view> args, std::ostream& out,
                      std::ostream& err, const CloudCommandEnv& env);

} // namespace rp
