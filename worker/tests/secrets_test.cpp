#include <rp/secrets.hpp>

#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace {

// The field of Secrets that `name` fills.
const std::optional<std::string>& field_for(const rp::Secrets& secrets, std::string_view name)
{
    if (name == rp::kEnvVeeamUsername) {
        return secrets.veeam_username;
    }
    if (name == rp::kEnvVeeamPassword) {
        return secrets.veeam_password;
    }
    return secrets.graph_client_secret;
}

} // namespace

TEST_CASE("the secret variables are the three documented names", "[secrets]")
{
    REQUIRE(rp::kSecretEnvVars[0] == "RP_VEEAM_USERNAME");
    REQUIRE(rp::kSecretEnvVars[1] == "RP_VEEAM_PASSWORD");
    REQUIRE(rp::kSecretEnvVars[2] == "RP_GRAPH_CLIENT_SECRET");
}

TEST_CASE("load_secrets_from_env leaves an unset or empty variable empty", "[secrets]")
{
    const std::string_view name = GENERATE(rp::kEnvVeeamUsername, rp::kEnvVeeamPassword,
                                           rp::kEnvGraphClientSecret);
    // On Windows, setting a variable to "" through the CRT removes it.
    const std::optional<std::string> value = GENERATE(std::optional<std::string>{},
                                                      std::optional<std::string>{""});
    CAPTURE(name, value.has_value());
    const rp::test::ScopedEnv env(name, value);

    REQUIRE_FALSE(field_for(rp::load_secrets_from_env(), name).has_value());
}

TEST_CASE("load_secrets_from_env reads each variable into its own field", "[secrets]")
{
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, "user-5b1a");
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, "password-5b1a");
    const rp::test::ScopedEnv graph(rp::kEnvGraphClientSecret, "graph-5b1a");

    const rp::Secrets secrets = rp::load_secrets_from_env();
    REQUIRE(secrets.veeam_username == "user-5b1a");
    REQUIRE(secrets.veeam_password == "password-5b1a");
    REQUIRE(secrets.graph_client_secret == "graph-5b1a");
}

TEST_CASE("load_secrets_from_env reads a variable when the others are unset", "[secrets]")
{
    const std::string_view name = GENERATE(rp::kEnvVeeamUsername, rp::kEnvVeeamPassword,
                                           rp::kEnvGraphClientSecret);
    CAPTURE(name);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, std::nullopt);
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, std::nullopt);
    const rp::test::ScopedEnv graph(rp::kEnvGraphClientSecret, std::nullopt);
    const rp::test::ScopedEnv env(name, "value with spaces & symbols = !");

    const rp::Secrets secrets = rp::load_secrets_from_env();
    for (const std::string_view other : rp::kSecretEnvVars) {
        CAPTURE(other);
        if (other == name) {
            REQUIRE(field_for(secrets, other) == "value with spaces & symbols = !");
        } else {
            REQUIRE_FALSE(field_for(secrets, other).has_value());
        }
    }
}

TEST_CASE("ScopedEnv restores the variable it changed", "[secrets]")
{
    const std::string name = "RP_TEST_SCOPED_ENV_7c3d";
    {
        const rp::test::ScopedEnv outer(name, "outer");
        {
            const rp::test::ScopedEnv inner(name, "inner");
            REQUIRE(rp::test::get_env(name) == "inner");
        }
        REQUIRE(rp::test::get_env(name) == "outer");
    }
    REQUIRE_FALSE(rp::test::get_env(name).has_value());
}

TEST_CASE("mask_secret never reveals the value or its length", "[secrets]")
{
    const std::optional<std::string> secret = GENERATE(std::optional<std::string>{"a"},
                                                       std::optional<std::string>{"p@ss"},
                                                       std::optional<std::string>{std::string(200, 'x')});
    REQUIRE(rp::mask_secret(secret) == "**** (set)");
}

TEST_CASE("mask_secret reports an unset or empty secret as not set", "[secrets]")
{
    const std::optional<std::string> secret = GENERATE(std::optional<std::string>{},
                                                       std::optional<std::string>{""});
    REQUIRE(rp::mask_secret(secret) == "(not set)");
}
