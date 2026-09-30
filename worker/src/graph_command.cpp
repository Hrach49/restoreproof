#include <rp/graph_command.hpp>

#include <rp/cli.hpp>
#include <rp/client_assertion.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/graph_download.hpp>
#include <rp/graph_errors.hpp>
#include <rp/graph_targets.hpp>

#include "command_config.hpp"
#include "text_table.hpp"

#include <chrono>
#include <cstddef>
#include <format>
#include <memory>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp {

namespace {

using graph::FoundItem;

// Whether `args` are `list` followed by `--hash`, `--config <path>` and
// `--record <dir>` in any order, each at most once; sets `hash` and the paths
// given, in UTF-8.
bool parse_list_args(std::span<const std::string_view> args, bool& hash,
                     std::optional<std::string_view>& config_arg,
                     std::optional<std::string_view>& record_arg)
{
    if (args.empty() || args[0] != "list") {
        return false;
    }
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--hash" && !hash) {
            hash = true;
        } else if (args[i] == "--config" && !config_arg && i + 1 < args.size()) {
            config_arg = args[++i];
        } else if (args[i] == "--record" && !record_arg && i + 1 < args.size()) {
            record_arg = args[++i];
        } else {
            return false;
        }
    }
    return true;
}

// The download client of a listing without --hash, which downloads nothing:
// the real one is never made, so it can't fail the listing.
class NoDownloads final : public IHttpClient {
public:
    HttpResponse send(const HttpRequest&) override
    {
        throw std::logic_error("a download without --hash");
    }
};

// what() is safe to print: GraphError's message went through rp::redact() and
// never holds a token, the assertion or a download link.
int report_graph_error(std::ostream& err, const graph::GraphError& e, int code)
{
    err << "graph error: " << e.what() << '\n';
    return code;
}

// What the three restore targets hold, in the order they are printed.
struct Listing {
    std::vector<FoundItem> mail;
    std::vector<FoundItem> sharepoint;
    std::vector<FoundItem> onedrive;
};

// Graph's text as a cell; "-" when it's missing or empty.
std::string cell_or_dash(const std::optional<std::string>& text)
{
    return text && !text->empty() ? table_cell(*text) : std::string{"-"};
}

// One location: its heading, then, if it holds anything, its column header
// and rows, indented, then a blank line.
std::string format_location(std::string_view where, std::vector<std::string> columns,
                            const std::vector<FoundItem>& items, bool hash,
                            std::vector<std::string> (*cells)(const FoundItem&))
{
    std::string text = std::format("{}: {} item(s)\n", where, items.size());
    if (!items.empty()) {
        if (hash) {
            columns.push_back("SHA256");
            columns.push_back("RULE");
        }
        std::vector<TableRow> rows{{"  ", std::move(columns)}};
        for (const FoundItem& item : items) {
            std::vector<std::string> row = cells(item);
            if (hash) {
                row.push_back(item.sha256);
                row.push_back(item.sha256_rule);
            }
            rows.push_back({"  ", std::move(row)});
        }
        text += format_table(rows);
    }
    return text + '\n';
}

std::vector<std::string> mail_cells(const FoundItem& item)
{
    const bool has_subject = item.subject && !item.subject->empty();
    return {cell_or_dash(item.received_at), cell_or_dash(item.sender),
            has_subject ? table_cell(*item.subject) : std::string{"(no subject)"},
            table_cell(item.id)};
}

std::vector<std::string> file_cells(const FoundItem& item)
{
    return {cell_or_dash(item.name),
            item.size_bytes ? std::to_string(*item.size_bytes) : std::string{"-"},
            table_cell(item.id)};
}

// The three tables, then the summary line.
std::string format_listing(std::string_view mailbox, const Listing& listing, bool hash)
{
    std::string text =
        format_location(std::format("Mail ({}, Inbox)", table_cell(mailbox)),
                        {"RECEIVED", "SENDER", "SUBJECT", "ID"}, listing.mail, hash, mail_cells);
    text += format_location("SharePoint (RestoreTarget library)", {"NAME", "SIZE", "ID"},
                            listing.sharepoint, hash, file_cells);
    text += format_location("OneDrive (RestoreTarget folder)", {"NAME", "SIZE", "ID"},
                            listing.onedrive, hash, file_cells);
    text += std::format("{} item(s) in the three restore targets\n",
                        listing.mail.size() + listing.sharepoint.size() +
                            listing.onedrive.size());
    return text;
}

} // namespace

GraphCommandEnv default_graph_command_env()
{
    GraphCommandEnv env;
    env.default_config_path = default_config_path;
    env.load_secrets = load_secrets_from_env;
    env.make_graph_http = [](std::shared_ptr<spdlog::logger> logger) {
        return graph::make_graph_http_client(std::move(logger));
    };
    env.make_download_http = graph::make_download_http_client;
    env.client_options.logger = make_command_logger();
    return env;
}

namespace {

// The command but for what --record wrote, which run_graph_command prints
// last: `recorder` is set once the recording is open.
int run_list(std::span<const std::string_view> args, std::ostream& out, std::ostream& err,
             const GraphCommandEnv& env, std::shared_ptr<FixtureRecorder>& recorder)
{
    bool hash = false;
    std::optional<std::string_view> config_arg;
    std::optional<std::string_view> record_arg;
    if (!parse_list_args(args, hash, config_arg, record_arg)) {
        err << kCliUsage;
        return exit_code::usage;
    }

    // Never spdlog's default logger, which writes to stdout, where the tables are.
    graph::GraphClientOptions client_options = env.client_options;
    if (!client_options.logger) {
        client_options.logger = make_command_logger();
    }
    const std::shared_ptr<spdlog::logger>& logger = client_options.logger;
    Config config;
    std::optional<graph::ClientCertificate> certificate;
    try {
        config = load_config(command_config_path(config_arg, env.default_config_path));
        const auto wall_now = client_options.wall_now ? client_options.wall_now()
                                                      : std::chrono::system_clock::now();
        // A CertificateError is a ConfigError: an unset or unusable certificate
        // is found here, before any request.
        const Secrets secrets = env.load_secrets();
        certificate = graph::certificate_from_secrets(secrets, wall_now, logger);
        recorder = open_recording(record_arg, hash ? "graph list --hash" : "graph list", secrets);
    } catch (const ConfigError& e) {
        err << "config error: " << e.what() << '\n';
        return exit_code::config;
    } catch (...) {
        // Not a ConfigError, so its message may not be safe to show.
        err << "config error: unexpected failure\n";
        return exit_code::config;
    }

    // Everything that can throw is in here, the tables' formatting and
    // printing included, so no exception escapes.
    try {
        // Declared in this order so the reader and the client, which hold
        // references to the HTTP clients, go first.
        // Downloads are recorded as their size and SHA-256 only, never the bytes.
        const std::unique_ptr<IHttpClient> http =
            recorded(env.make_graph_http(logger), recorder, "graph");
        const std::unique_ptr<IHttpClient> download =
            hash ? recorded(env.make_download_http(), recorder, "download", RecordedBody::digest)
                 : std::make_unique<NoDownloads>();
        if (!http || !download) {
            throw std::logic_error("no HTTP client");
        }
        graph::GraphClient client(*http, config.graph_tenant_id, config.graph_client_id,
                                  std::move(*certificate), client_options);
        graph::TargetReaderOptions options;
        options.logger = logger;
        options.hash_items = hash;
        options.download.logger = logger;
        graph::TargetReader reader(client, *download,
                                   connector::RestoreTargets::from_config(config), options);
        // Every list first, in the order printed: a failure prints no partial table.
        const Listing listing{reader.list_mail(), reader.list_sharepoint(), reader.list_onedrive()};
        out << format_listing(config.test_mailbox, listing, hash);
        // A full disk or a closed pipe: never exit 0 with a short listing.
        if (!out.flush()) {
            throw std::runtime_error("writing the tables failed");
        }
        return exit_code::ok;
    } catch (const graph::AuthError& e) {
        return report_graph_error(err, e, exit_code::auth);
    } catch (const graph::PermissionError& e) {
        return report_graph_error(err, e, exit_code::auth);
    } catch (const graph::TransientError& e) {
        return report_graph_error(err, e, exit_code::transient);
    } catch (const graph::GraphError& e) {
        return report_graph_error(err, e, exit_code::service);
    } catch (...) {
        // Its message, if it has one, may not be safe to show.
        err << "error: unexpected failure\n";
        return exit_code::config;
    }
}

} // namespace

int run_graph_command(std::span<const std::string_view> args, std::ostream& out,
                      std::ostream& err, const GraphCommandEnv& env)
{
    std::shared_ptr<FixtureRecorder> recorder;
    const int code = run_list(args, out, err, env, recorder);
    return finish_recording(recorder.get(), out, err, code);
}

} // namespace rp
