#include <rp/vault_command.hpp>

#include <rp/cert_export.hpp>
#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/secrets.hpp>
#include <rp/vault.hpp>

#include "command_config.hpp"
#include "console_input.hpp"
#include "path_utf8.hpp"
#include "text_table.hpp"

#include <format>
#include <optional>
#include <ostream>
#include <string>
#include <system_error>
#include <utility>

namespace rp {

namespace {

// Wipes every value of the Secrets it holds when it goes.
struct WipedSecrets {
    Secrets secrets;
    ~WipedSecrets()
    {
        for (const std::string_view name : kSecretNames) {
            std::optional<std::string>* field = secret_field(secrets, name);
            if (*field) {
                secure_wipe(**field);
            }
        }
    }
};

struct VaultArgs {
    std::string_view subcommand;
    std::string_view operand; // the name, or the account; empty for list and test
    std::optional<std::string_view> vault;
};

// nullopt for a command line the command doesn't take.
std::optional<VaultArgs> parse_vault_args(std::span<const std::string_view> args)
{
    if (args.empty()) {
        return std::nullopt;
    }
    VaultArgs parsed;
    parsed.subcommand = args[0];
    std::size_t next = 1;
    if (parsed.subcommand == "set" || parsed.subcommand == "remove" ||
        parsed.subcommand == "grant") {
        if (args.size() < 2 || args[1].starts_with("--")) {
            return std::nullopt;
        }
        parsed.operand = args[1];
        next = 2;
    } else if (parsed.subcommand != "list" && parsed.subcommand != "test") {
        return std::nullopt;
    }
    const std::optional<CommandOptions> options = parse_options(args.subspan(next), {"--vault"});
    if (!options) {
        return std::nullopt;
    }
    parsed.vault = options->value("--vault");
    if (parsed.vault && parsed.vault->empty()) {
        return std::nullopt;
    }
    return parsed;
}

std::string names_list()
{
    std::string names;
    for (const std::string_view name : kSecretNames) {
        names += names.empty() ? "" : ", ";
        names += name;
    }
    return names;
}

// The value for `set`, or the exit code with its line on `err`.
std::optional<std::string> value_for(std::string_view name, std::ostream& err,
                                     const VaultCommandEnv& env)
{
    SecretValue got = env.read_secret(name);
    std::string problem;
    switch (got.state) {
    case SecretValue::State::ok:
        return std::move(got.value);
    case SecretValue::State::empty:
        problem = "the value is empty";
        break;
    case SecretValue::State::too_long:
        problem = "the value is longer than " + std::to_string(kMaxVaultValueBytes) + " bytes";
        break;
    case SecretValue::State::not_unicode:
        problem = "the value isn't valid Unicode";
        break;
    case SecretValue::State::not_utf8:
        problem = "the value isn't valid UTF-8";
        break;
    case SecretValue::State::failed:
        problem = "the value couldn't be read";
        break;
    }
    secure_wipe(got.value);
    err << "vault error: " << problem << '\n';
    return std::nullopt;
}

// The vault read, or an empty one when the file isn't there.
Secrets read_or_empty(const std::filesystem::path& file)
{
    std::error_code ec;
    if (!std::filesystem::exists(file, ec)) {
        return {};
    }
    return read_vault(file);
}

int run_set(std::string_view name, const std::filesystem::path& file, std::string_view shown,
            std::ostream& out, std::ostream& err, const VaultCommandEnv& env)
{
    std::optional<std::string> value = value_for(name, err, env);
    if (!value) {
        return exit_code::config;
    }
    WipedSecrets held{read_or_empty(file)};
    *secret_field(held.secrets, name) = std::move(*value);
    write_vault(file, held.secrets);
    out << "set " << name << " in " << shown << '\n';
    return exit_code::ok;
}

int run_remove(std::string_view name, const std::filesystem::path& file, std::string_view shown,
               std::ostream& out)
{
    WipedSecrets held{read_vault(file)};
    std::optional<std::string>* field = secret_field(held.secrets, name);
    if (!*field) {
        out << name << " was not in " << shown << "; nothing changed\n";
        return exit_code::ok;
    }
    secure_wipe(**field);
    field->reset();
    write_vault(file, held.secrets);
    out << "removed " << name << " from " << shown << '\n';
    return exit_code::ok;
}

int run_list(const std::filesystem::path& file, std::ostream& out)
{
    const WipedSecrets held{read_vault(file)};
    for (const std::string_view name : kSecretNames) {
        if (secret_field(held.secrets, name)->has_value()) {
            out << name << '\n';
        }
    }
    return exit_code::ok;
}

int run_test(const std::filesystem::path& file, std::string_view shown, std::ostream& out)
{
    const WipedSecrets held{read_vault(file)};
    out << "vault " << shown << ": ok\n";
    for (const std::string_view name : kSecretNames) {
        out << std::format("{:<26}{}\n", name, mask_secret(*secret_field(held.secrets, name)));
    }
    return exit_code::ok;
}

int run_grant(std::string_view account, const std::filesystem::path& file,
              std::string_view shown, std::ostream& out)
{
    grant_vault_read(file, account);
    out << "granted read on " << shown << " to " << table_cell(account) << '\n';
    return exit_code::ok;
}

} // namespace

// SecretValue::State is SecretLineState, which stays out of the header.
static_assert(static_cast<int>(SecretValue::State::ok) == static_cast<int>(SecretLineState::ok));
static_assert(static_cast<int>(SecretValue::State::empty) ==
              static_cast<int>(SecretLineState::empty));
static_assert(static_cast<int>(SecretValue::State::too_long) ==
              static_cast<int>(SecretLineState::too_long));
static_assert(static_cast<int>(SecretValue::State::not_unicode) ==
              static_cast<int>(SecretLineState::not_unicode));
static_assert(static_cast<int>(SecretValue::State::not_utf8) ==
              static_cast<int>(SecretLineState::not_utf8));
static_assert(static_cast<int>(SecretValue::State::failed) ==
              static_cast<int>(SecretLineState::failed));

VaultCommandEnv default_vault_command_env()
{
    VaultCommandEnv env;
    env.default_vault_path = default_vault_path;
    env.read_secret = [](std::string_view name) {
        const SecretLine line =
            read_secret_line("value for " + std::string{name} + " (not shown): ",
                             kMaxVaultValueBytes);
        SecretValue value;
        value.state = static_cast<SecretValue::State>(line.state);
        value.value = line.value;
        return value;
    };
    return env;
}

int run_vault_command(std::span<const std::string_view> args, std::ostream& out,
                      std::ostream& err, const VaultCommandEnv& env)
{
    const std::optional<VaultArgs> parsed = parse_vault_args(args);
    if (!parsed) {
        err << kCliUsage;
        return exit_code::usage;
    }
    const Secrets probe;
    if ((parsed->subcommand == "set" || parsed->subcommand == "remove") &&
        secret_field(probe, parsed->operand) == nullptr) {
        err << "usage error: the name must be one of " << names_list() << '\n';
        return exit_code::usage;
    }
    // A --vault path that isn't UTF-8 is this command's own line, not a
    // ConfigError's (command_vault_path would say "the --vault path ..." too,
    // but after "config error: ").
    std::filesystem::path file;
    if (parsed->vault) {
        const std::optional<std::filesystem::path> given = path_from_utf8(*parsed->vault);
        if (!given) {
            err << "vault error: the --vault path is not valid UTF-8\n";
            return exit_code::config;
        }
        file = *given;
    }
    // One return after the handler (see signer.cpp): a return inside a catch
    // leaves its closing braces as lines no test runs.
    int code = exit_code::config;
    try {
        if (!parsed->vault) {
            file = env.default_vault_path();
        }
        const std::string shown = path_to_utf8(file);
        if (parsed->subcommand == "set") {
            code = run_set(parsed->operand, file, shown, out, err, env);
        } else if (parsed->subcommand == "remove") {
            code = run_remove(parsed->operand, file, shown, out);
        } else if (parsed->subcommand == "list") {
            code = run_list(file, out);
        } else if (parsed->subcommand == "test") {
            code = run_test(file, shown, out);
        } else {
            code = run_grant(parsed->operand, file, shown, out);
        }
    } catch (const ConfigError& e) {
        err << "vault error: " << e.what() << '\n';
    }
    return code;
}

} // namespace rp
