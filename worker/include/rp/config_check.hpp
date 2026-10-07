#pragma once

#include <rp/secrets.hpp>

#include <filesystem>
#include <functional>
#include <iosfwd>
#include <span>
#include <string_view>

namespace rp {

// What `config check` reaches outside itself. run_cli passes
// default_config_check_env(); tests pass temp files, so they never touch
// ProgramData.
struct ConfigCheckEnv {
    // The config file without --config (rp::default_config_path). Called only
    // then, and only after the arguments parsed.
    std::function<std::filesystem::path()> default_config_path;
    // The vault without --vault (rp::default_vault_path, W4.5). Called only
    // then, after the config is read and printed.
    std::function<std::filesystem::path()> default_vault_path;
    // rp::read_vault.
    std::function<Secrets(const std::filesystem::path& vault)> load_secrets;
};

// The real environment: rp::default_config_path, rp::default_vault_path,
// rp::read_vault.
ConfigCheckEnv default_config_check_env();

// `rpworker config ...`. `args` is what follows "config" on the command line,
// in UTF-8; the only subcommand is `check [--config <path>] [--vault <file>]`
// (each at most once, in any order). A --config or --vault path that isn't
// valid UTF-8 fails the check ("config error: the --config path is not valid
// UTF-8"). Without --config it reads the path env.default_config_path returns,
// called only then, so usage errors and --config never look up ProgramData;
// --vault likewise.
//
// `check` loads the config and prints every config field to `out`, then
// reads the vault (W4.5) and prints "secrets (vault <file>; values are never
// shown):" and the five secrets' names, each masked (rp::mask_secret), in
// rp::kSecretNames' order. Returns (rp::exit_code) 0 on success, 64 with the
// usage line (rp::kCliUsage) on `err` for arguments it doesn't understand,
// and 1 when the check fails: "config error: <message>" on `err` for a
// ConfigError (one from a default path, a vault that can't be used
// (rp::VaultError's messages) included; a vault error comes after the config's
// settings are already on `out`), "config error: unexpected failure" for any
// other exception, whose message is never shown. No exception escapes.
int run_config_command(std::span<const std::string_view> args, std::ostream& out, std::ostream& err,
                       const ConfigCheckEnv& env);

} // namespace rp
