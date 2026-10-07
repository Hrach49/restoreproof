#include <rp/config_check.hpp>

#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/secrets.hpp>
#include <rp/vault.hpp>

#include "command_config.hpp"
#include "path_utf8.hpp"

#include <exception>
#include <format>
#include <optional>
#include <ostream>
#include <string>

namespace rp {

namespace {

// `check [--config <path>] [--vault <file>]`'s options; nullopt for any
// other command line.
std::optional<CommandOptions> parse_check_args(std::span<const std::string_view> args)
{
    if (args.empty() || args[0] != "check") {
        return std::nullopt;
    }
    return parse_options(args.subspan(1), {"--config", "--vault"});
}

template <typename Value>
void print_setting(std::ostream& out, std::string_view label, const Value& value)
{
    out << std::format("{:<26}{}\n", label, value);
}

int report(std::ostream& err, const std::exception_ptr& error)
{
    try {
        std::rethrow_exception(error);
    } catch (const ConfigError& e) {
        err << "config error: " << e.what() << '\n';
    } catch (const std::exception&) {
        // Not a ConfigError, so its message may not be safe to show.
        err << "config error: unexpected failure\n";
    }
    return exit_code::config;
}

} // namespace

ConfigCheckEnv default_config_check_env()
{
    return {default_config_path, default_vault_path, read_vault};
}

int run_config_command(std::span<const std::string_view> args, std::ostream& out, std::ostream& err,
                       const ConfigCheckEnv& env)
{
    const std::optional<CommandOptions> options = parse_check_args(args);
    if (!options) {
        err << kCliUsage;
        return exit_code::usage;
    }
    const std::optional<std::string_view> config_arg = options->value("--config");
    const std::optional<std::string_view> vault_arg = options->value("--vault");

    // default_config_path() is called only here, so usage errors and --config
    // never look up ProgramData. Nothing thrown here may escape to main().
    std::filesystem::path path;
    Config config;
    try {
        path = command_config_path(config_arg, env.default_config_path);
        config = load_config(path);
    } catch (...) {
        return report(err, std::current_exception());
    }

    out << "config file: " << path_to_utf8(path) << '\n';
    print_setting(out, "cloud_url", config.cloud_url);
    print_setting(out, "veeam_url", config.veeam_url);
    print_setting(out, "veeam_org_name", config.veeam_org_name);
    print_setting(out, "graph_tenant_id", config.graph_tenant_id);
    print_setting(out, "graph_client_id", config.graph_client_id);
    print_setting(out, "test_mailbox", config.test_mailbox);
    print_setting(out, "test_site_id", config.test_site_id);
    print_setting(out, "test_library_id", config.test_library_id);
    print_setting(out, "test_onedrive_drive_id", config.test_onedrive_drive_id);
    print_setting(out, "test_onedrive_folder_id", config.test_onedrive_folder_id);
    print_setting(out, "poll_interval_s", config.poll_interval_s);
    print_setting(out, "heartbeat_interval_s", config.heartbeat_interval_s);
    print_setting(out, "sample_mail", config.sample_mail);
    print_setting(out, "sample_sp", config.sample_sp);
    print_setting(out, "sample_od", config.sample_od);
    print_setting(out, "log_level", config.log_level);
    print_setting(out, "veeam_ca_file", config.veeam_ca_file.value_or("(not set)"));
    print_setting(out, "veeam_cert_sha256", config.veeam_cert_sha256.value_or("(not set)"));
    print_setting(out, "tsa_url", config.tsa_url.value_or("(not set)"));
    print_setting(out, "tsa_ca_file", config.tsa_ca_file.value_or("(not set)"));
    print_setting(out, "cloud_ca_file", config.cloud_ca_file.value_or("(not set)"));
    print_setting(out, "screenshots_enabled", config.screenshots_enabled);

    // W4.5: the vault, after the settings, so a fresh installation's check
    // still shows its config and then names what is missing.
    std::filesystem::path vault;
    Secrets secrets;
    try {
        vault = command_vault_path(vault_arg, env.default_vault_path);
        secrets = env.load_secrets(vault);
    } catch (...) {
        return report(err, std::current_exception());
    }
    out << "secrets (vault " << path_to_utf8(vault) << "; values are never shown):\n";
    // Only whether each is set: config check stays offline and never opens the
    // PFX (rp::graph::certificate_from_secrets does, before any Graph call),
    // nor parses the signing key (W4.3: only `test --evidence` and `signer
    // public-key` do).
    for (const std::string_view name : kSecretNames) {
        print_setting(out, name, mask_secret(*secret_field(secrets, name)));
    }
    return exit_code::ok;
}

} // namespace rp
