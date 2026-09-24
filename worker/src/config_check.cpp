#include <rp/config_check.hpp>

#include <rp/config.hpp>
#include <rp/secrets.hpp>

#include "path_utf8.hpp"
#include "utf16.hpp"

#include <exception>
#include <format>
#include <optional>
#include <ostream>
#include <string>
#include <utility>

namespace rp {

namespace {

constexpr std::string_view kUsage =
    "usage: rpworker --version | rpworker config check [--config <path>]\n";

// Whether `args` are `check` or `check --config <path>`; for the latter,
// sets `config_arg` to the path as given, in UTF-8.
bool parse_check_args(std::span<const std::string_view> args,
                      std::optional<std::string_view>& config_arg)
{
    if (args.size() == 1 && args[0] == "check") {
        return true;
    }
    if (args.size() == 3 && args[0] == "check" && args[1] == "--config") {
        config_arg = args[2];
        return true;
    }
    return false;
}

// The --config argument as a path.
std::filesystem::path config_arg_to_path(std::string_view config_arg)
{
    std::optional<std::filesystem::path> path = path_from_utf8(config_arg);
    if (!path) {
        throw ConfigError("", "the --config path is not valid UTF-8");
    }
    return std::move(*path);
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
    std::optional<std::string_view> config_arg;
    if (!parse_check_args(args, config_arg)) {
        err << kUsage;
        return 2;
    }

    // default_path() is called only here, so usage errors and --config never
    // look up ProgramData. Nothing thrown here may escape to main().
    std::filesystem::path path;
    Config config;
    Secrets secrets;
    try {
        path = config_arg ? config_arg_to_path(*config_arg) : default_path();
        config = load_config(path);
        secrets = load_secrets_from_env();
    } catch (const ConfigError& e) {
        err << "config error: " << e.what() << '\n';
        return 1;
    } catch (const std::exception&) {
        // Not a ConfigError, so its message may not be safe to show.
        err << "config error: unexpected failure\n";
        return 1;
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
    out << "secrets (environment variables; values are never shown):\n";
    print_setting(out, kEnvVeeamUsername, mask_secret(secrets.veeam_username));
    print_setting(out, kEnvVeeamPassword, mask_secret(secrets.veeam_password));
    print_setting(out, kEnvGraphClientSecret, mask_secret(secrets.graph_client_secret));
    return 0;
}

} // namespace rp
