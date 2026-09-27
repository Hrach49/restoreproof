// W1.7: rp::connector::ConnectorRegistry, which maps a connector's name to a
// factory, with fake factories. The registered "veeam_m365" is tested with
// the connector in veeam_m365_connector_test.cpp.

#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/secrets.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using Catch::Matchers::Message;

namespace {

namespace connector = rp::connector;

class NamedConnector final : public connector::IConnector {
public:
    explicit NamedConnector(std::string name) : name_(std::move(name)) {}

    connector::ConnectorInfo describe() const override { return {name_, "1"}; }

    std::vector<connector::RestorePoint> list_restore_points(const std::string&) override
    {
        return {};
    }

    connector::RestoreResult restore_sample(const connector::RestoreSpec&) override
    {
        throw connector::NotImplementedError("not in this fake");
    }

private:
    std::string name_;
};

connector::ConnectorFactory factory_for(std::string name)
{
    return [name](const rp::Config&, const rp::Secrets&, const connector::ConnectorOptions&) {
        return std::make_unique<NamedConnector>(name);
    };
}

} // namespace

// --- Failure paths ---------------------------------------------------------------

TEST_CASE("an unknown connector name is refused, naming the known ones", "[connector_registry]")
{
    connector::ConnectorRegistry registry;
    registry.add("beta", factory_for("beta"));
    registry.add("alpha", factory_for("alpha"));
    const auto [name, message] = GENERATE(table<std::string, std::string>({
        {"gamma", R"(unknown connector "gamma" (known: alpha, beta))"},
        // Names match exactly: no case folding, no trimming.
        {"Alpha", R"(unknown connector "Alpha" (known: alpha, beta))"},
        {"alpha ", R"(unknown connector "alpha " (known: alpha, beta))"},
        {"", R"(unknown connector "" (known: alpha, beta))"},
        // A name that could forge or hide text isn't echoed.
        {"a\nb", "unknown connector (known: alpha, beta)"},
        {"caf\xc3\xa9", "unknown connector (known: alpha, beta)"},
        {std::string(65, 'x'), "unknown connector (known: alpha, beta)"},
    }));
    CAPTURE(name);

    try {
        (void)registry.create(name, rp::Config{}, rp::Secrets{});
        FAIL("no exception");
    } catch (const connector::UnknownConnectorError& e) {
        REQUIRE(std::string{e.what()} == message);
        REQUIRE(e.name() == name);
    }
}

TEST_CASE("an empty registry says it knows none", "[connector_registry]")
{
    const connector::ConnectorRegistry registry;
    REQUIRE_THROWS_MATCHES(registry.create("veeam_m365", rp::Config{}, rp::Secrets{}),
                           connector::UnknownConnectorError,
                           Message(R"(unknown connector "veeam_m365" (known: none))"));
}

TEST_CASE("a registry refuses an empty name, a null factory and a duplicate",
          "[connector_registry]")
{
    connector::ConnectorRegistry registry;
    registry.add("alpha", factory_for("alpha"));

    REQUIRE_THROWS_MATCHES(registry.add("", factory_for("x")), std::invalid_argument,
                           Message("a connector needs a name"));
    REQUIRE_THROWS_MATCHES(registry.add("beta", nullptr), std::invalid_argument,
                           Message(R"(connector "beta" has no factory)"));
    REQUIRE_THROWS_MATCHES(registry.add("alpha", factory_for("other")), std::invalid_argument,
                           Message(R"(connector "alpha" is already registered)"));
    // The first registration stands.
    REQUIRE(registry.create("alpha", rp::Config{}, rp::Secrets{})->describe().name == "alpha");
    REQUIRE(registry.names() == std::vector<std::string>{"alpha"});
}

TEST_CASE("a factory that returns no connector is a logic error", "[connector_registry]")
{
    connector::ConnectorRegistry registry;
    registry.add("broken", [](const rp::Config&, const rp::Secrets&,
                              const connector::ConnectorOptions&) {
        return std::unique_ptr<connector::IConnector>{};
    });
    REQUIRE_THROWS_MATCHES(registry.create("broken", rp::Config{}, rp::Secrets{}),
                           std::logic_error, Message(R"(connector "broken" made no connector)"));
}

// --- Happy paths -------------------------------------------------------------------

TEST_CASE("a registry creates the connector registered under a name", "[connector_registry]")
{
    connector::ConnectorRegistry registry;
    registry.add("beta", factory_for("beta"));
    registry.add("alpha", factory_for("alpha"));

    REQUIRE(registry.names() == std::vector<std::string>{"alpha", "beta"});
    const std::unique_ptr<connector::IConnector> made =
        registry.create("beta", rp::Config{}, rp::Secrets{});
    REQUIRE(made);
    REQUIRE(made->describe().name == "beta");
}

TEST_CASE("a factory gets the config, the secrets and the options", "[connector_registry]")
{
    rp::Config config;
    config.veeam_url = "https://veeam.test:4443";
    const rp::Secrets secrets{"user", "pass", std::nullopt};
    connector::ConnectorOptions options;
    options.jitter = [] { return 0.25; };

    std::string seen_url;
    std::optional<std::string> seen_user;
    double seen_jitter = -1;
    connector::ConnectorRegistry registry;
    registry.add("probe", [&](const rp::Config& c, const rp::Secrets& s,
                              const connector::ConnectorOptions& o) {
        seen_url = c.veeam_url;
        seen_user = s.veeam_username;
        seen_jitter = o.jitter();
        return std::make_unique<NamedConnector>("probe");
    });

    (void)registry.create("probe", config, secrets, options);
    REQUIRE(seen_url == "https://veeam.test:4443");
    REQUIRE(seen_user == std::optional<std::string>{"user"});
    REQUIRE(seen_jitter == 0.25);
}
