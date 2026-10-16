#pragma once

// `rpworker vault set|remove <name> | list | test | grant <account>`, each
// with `[--vault <file>]` (W4.5, docs/decisions.md 2026-10-07, point 4): the
// one way the seven secrets (rp/secrets.hpp) get into the DPAPI vault
// (rp/vault.hpp), out of it, and the one way another account is let read it.
// The value of `set` comes from the console without echo or from stdin,
// never from an argument. Strict (100% line): the reader of the value is a
// seam, the vault is the real one on a file the caller names.

#include <cstddef>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <span>
#include <string>
#include <string_view>

namespace rp {

// What `set` got for the value: the console's or the pipe's line
// (src/console_input.hpp's SecretLine, kept out of this header).
struct SecretValue {
    enum class State { ok, empty, too_long, not_unicode, not_utf8, failed };
    State state = State::failed;
    std::string value;
};

// What the commands reach outside themselves. run_cli passes
// default_vault_command_env(); tests pass a temp file's path and a reader
// that answers from a string.
struct VaultCommandEnv {
    // The vault without --vault (rp::default_vault_path). Called only then,
    // and only after the arguments parsed.
    std::function<std::filesystem::path()> default_vault_path;
    // Reads the value `set <name>` stores: rp::read_secret_line with the
    // prompt "value for <name> (not shown): " and kMaxVaultValueBytes. Called
    // once, after the arguments parsed and before the vault is read.
    std::function<SecretValue(std::string_view name)> read_secret;
};

// The real environment: rp::default_vault_path and the console or stdin.
VaultCommandEnv default_vault_command_env();

// `rpworker vault ...`. `args` is what follows "vault" on the command line, in
// UTF-8. `--vault <file>` names the vault (any order, once, never empty);
// without it the default is used. Prints to `out`:
//  - `set <name>`: reads the value, then the vault (none: an empty one),
//    puts the value under the name, writes, "set <name> in <file>";
//  - `remove <name>`: "removed <name> from <file>", or "<name> was not in
//    <file>; nothing changed";
//  - `list`: the names in the vault, one per line, in kSecretNames' order,
//    nothing for an empty vault; never a value or a length;
//  - `test`: "vault <file>: ok", then each of the seven names with
//    mask_secret's word, in config check's layout;
//  - `grant <account>`: a Read entry for the account on the file's ACL,
//    "granted read on <file> to <account>" (the account through table_cell).
// <file> is the path as given, or the default as UTF-8.
// Returns an rp::exit_code: 0; 64 with rp::kCliUsage on `err` for no
// subcommand, an unknown one, a word too many, a missing name or account, a
// name or account that starts with "--", or --vault without a file, empty or
// twice; 64 with "usage error: the name must be one of veeam_username,
// veeam_password, graph_cert_pfx_base64, graph_cert_password,
// signing_key_base64, cloud_install_token, cloud_api_token" for a name that
// isn't one of the seven (the word given is never echoed); 1 with one line on `err`: "vault error: the --vault path
// is not valid UTF-8", "vault error: <what()>" for a rp::VaultError (the
// messages on rp/vault.hpp) or a ConfigError from default_vault_path, and for
// `set` "vault error: the value is empty", "vault error: the value is longer
// than <kMaxVaultValueBytes> bytes", "vault error: the value isn't valid
// Unicode", "vault error: the value isn't valid UTF-8", "vault error: the
// value couldn't be read", each before the vault is touched. The value and
// the secrets read are wiped when the command ends. Nothing else is caught:
// what else is thrown is run_cli's "error: unexpected failure".
int run_vault_command(std::span<const std::string_view> args, std::ostream& out,
                      std::ostream& err, const VaultCommandEnv& env);

} // namespace rp
