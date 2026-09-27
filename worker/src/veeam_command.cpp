#include <rp/veeam_command.hpp>

#include <rp/cli.hpp>
#include <rp/config.hpp>

#include "command_config.hpp"
#include "control_chars.hpp"

#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <format>
#include <memory>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace rp {

namespace {

// Whether `args` are `list` or `list --config <path>`; for the latter, sets
// `config_arg` to the path as given, in UTF-8.
bool parse_list_args(std::span<const std::string_view> args,
                     std::optional<std::string_view>& config_arg)
{
    return !args.empty() && args[0] == "list" && parse_config_option(args.subspan(1), config_arg);
}

bool is_set(const std::optional<std::string>& secret) noexcept
{
    return secret && !secret->empty();
}

// what() is safe to print: VeeamError's message went through rp::redact().
int report_veeam_error(std::ostream& err, const VeeamError& e, int code)
{
    err << "veeam error: " << e.what() << '\n';
    return code;
}

// One organisation, its restore points (newest first), and whether it is the
// one veeam_org_name names.
struct OrgListing {
    Organization org;
    std::vector<RestorePoint> points;
    bool configured = false;
};

char ascii_lower(char c) noexcept
{
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

std::string ascii_lower(std::string_view text)
{
    std::string out(text);
    std::ranges::transform(out, out.begin(), [](char c) { return ascii_lower(c); });
    return out;
}

// Organisations by name, ASCII case-insensitively, then by ID.
bool org_less(const Organization& a, const Organization& b)
{
    return std::forward_as_tuple(ascii_lower(a.name), a.id) <
           std::forward_as_tuple(ascii_lower(b.name), b.id);
}

// Text from Veeam as a table cell: a control character (control_chars.hpp),
// which could forge, hide or reorder a line, becomes a space.
std::string cell(std::string_view text)
{
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size();) {
        if (const std::size_t length = control_character_length(text, i); length != 0) {
            out += ' ';
            i += length;
        } else {
            out += text[i];
            ++i;
        }
    }
    return out;
}

// The width of UTF-8 text in code points: every byte that isn't a
// continuation byte starts one.
std::size_t width(std::string_view text) noexcept
{
    return static_cast<std::size_t>(std::ranges::count_if(
        text, [](char c) { return (static_cast<unsigned char>(c) & 0xC0) != 0x80; }));
}

constexpr std::array<std::string_view, 8> kColumns{
    "ORGANIZATION", "BACKUP TIME", "EX", "SP", "OD", "TM", "LONG-TERM", "RESTORE POINT ID"};

struct Row {
    bool marked = false;
    std::array<std::string, kColumns.size()> cells;
};

std::string flag(bool set)
{
    return set ? "x" : "-";
}

// The table, then a blank line and the summary. Columns are left-aligned,
// padded to their widest cell and two spaces apart; no line ends in a space.
std::string format_listing(const std::vector<OrgListing>& listing)
{
    std::vector<Row> rows;
    Row header;
    std::ranges::copy(kColumns, header.cells.begin());
    rows.push_back(std::move(header));
    std::size_t point_count = 0;
    for (const OrgListing& entry : listing) {
        const std::string name = cell(entry.org.name);
        if (entry.points.empty()) {
            rows.push_back({entry.configured, {name, "(no restore points)"}});
        }
        for (const RestorePoint& point : entry.points) {
            rows.push_back({entry.configured,
                            {name, cell(point.backup_time), flag(point.is_exchange),
                             flag(point.is_sharepoint), flag(point.is_onedrive),
                             flag(point.is_teams), point.is_long_term_copy ? "yes" : "no",
                             cell(point.id)}});
        }
        point_count += entry.points.size();
    }

    std::string text;
    if (listing.empty()) {
        text = "no organisations in Veeam\n";
    } else {
        std::array<std::size_t, kColumns.size()> widths{};
        for (const Row& row : rows) {
            for (std::size_t i = 0; i < widths.size(); ++i) {
                widths[i] = std::max(widths[i], width(row.cells[i]));
            }
        }
        for (const Row& row : rows) {
            std::string line = row.marked ? "* " : "  ";
            for (std::size_t i = 0; i < widths.size(); ++i) {
                line += row.cells[i];
                if (i + 1 < widths.size()) {
                    line.append(widths[i] - width(row.cells[i]) + 2, ' ');
                }
            }
            line.erase(line.find_last_not_of(' ') + 1);
            text += line + '\n';
        }
    }
    text += std::format("\n{} organisation(s), {} restore point(s); * = veeam_org_name\n",
                        listing.size(), point_count);
    return text;
}

} // namespace

VeeamCommandEnv default_veeam_command_env()
{
    VeeamCommandEnv env;
    env.default_config_path = default_config_path;
    env.load_secrets = load_secrets_from_env;
    env.make_http = [](const HttpClientOptions& options) -> std::unique_ptr<IHttpClient> {
        return std::make_unique<HttpClient>(options);
    };
    // Not registered with spdlog, and not the default logger, which writes to
    // stdout.
    auto logger = std::make_shared<spdlog::logger>(
        "rpworker", std::make_shared<spdlog::sinks::stderr_sink_mt>());
    logger->set_level(spdlog::level::warn);
    env.client_options.logger = std::move(logger);
    return env;
}

int run_veeam_command(std::span<const std::string_view> args, std::ostream& out,
                      std::ostream& err, const VeeamCommandEnv& env)
{
    std::optional<std::string_view> config_arg;
    if (!parse_list_args(args, config_arg)) {
        err << kCliUsage;
        return exit_code::usage;
    }

    Config config;
    Secrets secrets;
    try {
        config = load_config(command_config_path(config_arg, env.default_config_path));
        secrets = env.load_secrets();
    } catch (const ConfigError& e) {
        err << "config error: " << e.what() << '\n';
        return exit_code::config;
    } catch (...) {
        // Not a ConfigError, so its message may not be safe to show.
        err << "config error: unexpected failure\n";
        return exit_code::config;
    }
    if (!is_set(secrets.veeam_username)) {
        err << "config error: " << kEnvVeeamUsername << " is not set\n";
        return exit_code::config;
    }
    if (!is_set(secrets.veeam_password)) {
        err << "config error: " << kEnvVeeamPassword << " is not set\n";
        return exit_code::config;
    }
    HttpClientOptions http_options;
    // TLS is never off: the CA file and the pin only choose what to trust.
    http_options.ca_file = config.veeam_ca_file;
    http_options.pinned_cert_sha256 = config.veeam_cert_sha256;
    http_options.logger = env.client_options.logger;
    http_options.sleep = env.client_options.sleep;
    http_options.jitter = env.client_options.jitter;

    // Declared in this order so the client, which holds a reference to the
    // HTTP client, goes first.
    std::unique_ptr<IHttpClient> http;
    std::unique_ptr<VeeamClient> client;
    int code = exit_code::ok;
    // Everything that can throw is in here, the table's formatting and
    // printing included, so no exception escapes.
    try {
        http = env.make_http(http_options);
        if (!http) {
            throw std::logic_error("no HTTP client");
        }
        client = std::make_unique<VeeamClient>(*http, config.veeam_url, *secrets.veeam_username,
                                               *secrets.veeam_password, env.client_options);
        std::vector<Organization> orgs = client->list_organizations();
        std::ranges::sort(orgs, org_less);
        // Every list first: a failure prints no partial table.
        std::vector<OrgListing> listing;
        for (Organization& org : orgs) {
            std::vector<RestorePoint> points = client->list_restore_points(org.id);
            const bool configured = ascii_lower(org.name) == ascii_lower(config.veeam_org_name);
            listing.push_back({std::move(org), std::move(points), configured});
        }
        // Before the logout: everything is read, so the table needn't wait for
        // Veeam to answer it.
        out << format_listing(listing);
        if (std::ranges::none_of(listing, &OrgListing::configured)) {
            err << "veeam error: organisation " << config.veeam_org_name
                << " (veeam_org_name) not found in Veeam\n";
            code = exit_code::veeam;
        }
    } catch (const AuthError& e) {
        code = report_veeam_error(err, e, exit_code::auth);
    } catch (const TransientError& e) {
        code = report_veeam_error(err, e, exit_code::transient);
    } catch (const VeeamError& e) {
        code = report_veeam_error(err, e, exit_code::veeam);
    } catch (...) {
        // Its message, if it has one, may not be safe to show.
        err << "error: unexpected failure\n";
        code = exit_code::config;
    }
    if (client) {
        client->logout();
    }
    return code;
}

} // namespace rp
