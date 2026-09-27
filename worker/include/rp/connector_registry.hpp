#pragma once

// Connectors by name (W1.7). The name comes from wherever the run is defined:
// hard-wired to kVeeamM365 for now, from the Cloud's job later (C5.6 sends
// each client's connector type). No Veeam header here either: the registry
// hands out IConnector.

#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>

#include <spdlog/logger.h>

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rp::connector {

// The Veeam Backup for Microsoft 365 connector's name.
inline constexpr std::string_view kVeeamM365 = "veeam_m365";

// What a connector may take from its caller besides the config and secrets.
// Every field may be left empty for the real thing.
struct ConnectorOptions {
    // Makes the HTTP client a connector talks through; null = rp::HttpClient.
    // The connector fills the options (its CA file and pin among them) and
    // owns the client.
    std::function<std::unique_ptr<IHttpClient>(const HttpClientOptions&)> make_http;
    // Where the connector's HTTP and client debug lines go; null = spdlog's
    // default logger at the time of the call. Every line is redacted.
    std::shared_ptr<spdlog::logger> logger;
    // The wait between retries; null = std::this_thread::sleep_for.
    std::function<void(std::chrono::milliseconds)> sleep;
    // Jitter for the retry delay, in [0, 1); null = uniform random.
    std::function<double()> jitter;
};

// Makes one connector. Throws ConfigError for config or secrets it can't work
// with (a missing secret names its variable, as `veeam list` does).
using ConnectorFactory = std::function<std::unique_ptr<IConnector>(
    const Config&, const Secrets&, const ConnectorOptions&)>;

// A name no connector is registered under. A configuration error, not a
// backup product's: exit code 1 (rp::exit_code::config) where a command meets
// it, and `error` for a run.
class UnknownConnectorError : public std::invalid_argument {
public:
    // `known`: the registered names, sorted.
    UnknownConnectorError(std::string name, const std::vector<std::string>& known);

    // The name as asked for. what() quotes it only when it is 1 to 64
    // printable ASCII characters, so it can't forge or hide text.
    const std::string& name() const noexcept;

private:
    std::string name_;
};

// Explicit, not self-registering: the linker drops unreferenced objects from
// a static library such as rpcore, and with them any registration they made.
class ConnectorRegistry {
public:
    // Throws std::invalid_argument for an empty name, a null factory or a name
    // already registered (the first stays).
    void add(std::string name, ConnectorFactory factory);

    // The connector registered under `name`, matched exactly (case and all).
    // Throws UnknownConnectorError for any other name, std::logic_error when
    // the factory returns null, and whatever the factory throws.
    std::unique_ptr<IConnector> create(std::string_view name, const Config& config,
                                       const Secrets& secrets,
                                       const ConnectorOptions& options = {}) const;

    // The registered names, sorted.
    std::vector<std::string> names() const;

private:
    std::map<std::string, ConnectorFactory, std::less<>> factories_;
};

// A registry with every connector the Worker has: kVeeamM365.
ConnectorRegistry default_connector_registry();

} // namespace rp::connector
