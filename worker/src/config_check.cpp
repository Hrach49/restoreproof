#include <rp/config_check.hpp>

#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/secrets.hpp>

#include "command_config.hpp"
#include "path_utf8.hpp"

#include <exception>
#include <format>
#include <optional>
#include <ostream>
#include <string>

namespace rp {

namespace {

// `check [--config <path>]`'s options; nullopt for any other command line.
std::optional<CommandOptions> parse_check_args(std::span<const std::string_view> args)
{
    if (args.empty() || args[0] != "check") {
        return std::nullopt;
    }
    return parse_options(args.subspan(1), {"--config"});
}

template <typename Value>
void print_setting(std::ostream& out, std::string_view label, const Value& value)
{
    out << std::format("{:<26}{}\n", label, value);
}

} // namespace

int run_config_command(std::span<const std::string_view> args, std::ostream& out, std::ostream& err,
                       const std::function<std::filesystem::path()>& default_path)
{
    const std::optional<CommandOptions> options = parse_check_args(args);
    if (!options) {
        err << kCliUsage;
        return exit_code::usage;
    }
    const std::optional<std::string_view> config_arg = options->value("--config");

    // default_path() is called only here, so usage errors and --config never
    // look up ProgramData. Nothing thrown here may escape to main().
    std::filesystem::path path;
    Config config;
    Secrets secrets;
    try {
        path = command_config_path(config_arg, default_path);
        config = load_config(path);
        secrets = load_secrets_from_env();
    } catch (const ConfigError& e) {
        err << "config error: " << e.what() << '\n';
        return exit_code::config;
    } catch (const std::exception&) {
        // Not a ConfigError, so its message may not be safe to show.
        err << "config error: unexpected failure\n";
        return exit_code::config;
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
    print_setting(out, "screenshots_enabled", config.screenshots_enabled);
    out << "secrets (environment variables; values are never shown):\n";
    print_setting(out, kEnvVeeamUsername, mask_secret(secrets.veeam_username));
    print_setting(out, kEnvVeeamPassword, mask_secret(secrets.veeam_password));
    // Only whether each is set: config check stays offline and never opens the
    // PFX (rp::graph::certificate_from_secrets does, before any Graph call).
    print_setting(out, kEnvGraphCertPfxBase64, mask_secret(secrets.graph_cert_pfx_base64));
    print_setting(out, kEnvGraphCertPassword, mask_secret(secrets.graph_cert_password));
    // Nor is the signing key parsed (W4.3): only `test --evidence` and `signer
    // public-key` do that.
    print_setting(out, kEnvSigningKeyBase64, mask_secret(secrets.signing_key_base64));
    return exit_code::ok;
}

} // namespace rp
