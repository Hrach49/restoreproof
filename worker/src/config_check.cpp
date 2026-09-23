#include <rp/config_check.hpp>

#include <rp/config.hpp>
#include <rp/secrets.hpp>

#include "path_utf8.hpp"

#include <format>
#include <optional>
#include <ostream>
#include <string>

namespace rp {

namespace {

constexpr std::string_view kUsage =
    "usage: rpworker --version | rpworker config check [--config <path>]\n";

// The path `check` should read: `default_path`, or the one --config names.
// nullopt for arguments it doesn't understand.
std::optional<std::filesystem::path> check_path(std::span<const std::string_view> args,
                                                const std::filesystem::path& default_path)
{
    if (args.size() == 1 && args[0] == "check") {
        return default_path;
    }
    if (args.size() == 3 && args[0] == "check" && args[1] == "--config") {
        // argv is in the ANSI code page, which is what path(std::string) expects.
        return std::filesystem::path(std::string{args[2]});
    }
    return std::nullopt;
}

template <typename Value>
void print_setting(std::ostream& out, std::string_view label, const Value& value)
{
    out << std::format("{:<26}{}\n", label, value);
}

} // namespace

int run_config_command(std::span<const std::string_view> args, std::ostream& out, std::ostream& err,
                       const std::filesystem::path& default_path)
{
    const std::optional<std::filesystem::path> path = check_path(args, default_path);
    if (!path) {
        err << kUsage;
        return 2;
    }

    Config config;
    try {
        config = load_config(*path);
    } catch (const ConfigError& e) {
        err << "config error: " << e.what() << '\n';
        return 1;
    }
    const Secrets secrets = load_secrets_from_env();

    out << "config file: " << path_to_utf8(*path) << '\n';
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
    out << "secrets (environment variables; values are never shown):\n";
    print_setting(out, kEnvVeeamUsername, mask_secret(secrets.veeam_username));
    print_setting(out, kEnvVeeamPassword, mask_secret(secrets.veeam_password));
    print_setting(out, kEnvGraphClientSecret, mask_secret(secrets.graph_client_secret));
    return 0;
}

} // namespace rp
