#include <rp/config.hpp>
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
    if (name == rp::kEnvGraphCertPfxBase64) {
        return secrets.graph_cert_pfx_base64;
    }
    return secrets.graph_cert_password;
}

} // namespace

TEST_CASE("the secret variables are the four documented names", "[secrets]")
{
    // The Graph app signs in with a certificate, not a client secret (W2.1).
    REQUIRE(rp::kSecretEnvVars.size() == 4);
    REQUIRE(rp::kSecretEnvVars[0] == "RP_VEEAM_USERNAME");
    REQUIRE(rp::kSecretEnvVars[1] == "RP_VEEAM_PASSWORD");
    REQUIRE(rp::kSecretEnvVars[2] == "RP_GRAPH_CERT_PFX_BASE64");
    REQUIRE(rp::kSecretEnvVars[3] == "RP_GRAPH_CERT_PASSWORD");
}

TEST_CASE("load_secrets_from_env leaves an unset or empty variable empty", "[secrets]")
{
    const std::string_view name = GENERATE(rp::kEnvVeeamUsername, rp::kEnvVeeamPassword,
                                           rp::kEnvGraphCertPfxBase64, rp::kEnvGraphCertPassword);
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
    const rp::test::ScopedEnv pfx(rp::kEnvGraphCertPfxBase64, "pfx-5b1a");
    const rp::test::ScopedEnv pfx_password(rp::kEnvGraphCertPassword, "pfx-password-5b1a");

    const rp::Secrets secrets = rp::load_secrets_from_env();
    REQUIRE(secrets.veeam_username == "user-5b1a");
    REQUIRE(secrets.veeam_password == "password-5b1a");
    REQUIRE(secrets.graph_cert_pfx_base64 == "pfx-5b1a");
    REQUIRE(secrets.graph_cert_password == "pfx-password-5b1a");
}

TEST_CASE("load_secrets_from_env reads a variable when the others are unset", "[secrets]")
{
    const std::string_view name = GENERATE(rp::kEnvVeeamUsername, rp::kEnvVeeamPassword,
                                           rp::kEnvGraphCertPfxBase64, rp::kEnvGraphCertPassword);
    CAPTURE(name);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, std::nullopt);
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, std::nullopt);
    const rp::test::ScopedEnv pfx(rp::kEnvGraphCertPfxBase64, std::nullopt);
    const rp::test::ScopedEnv pfx_password(rp::kEnvGraphCertPassword, std::nullopt);
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

TEST_CASE("load_secrets_from_env reads a PFX of several kilobytes whole", "[secrets]")
{
    // A 4096-bit key with its certificate chain is a few KB of Base64; the
    // variable may hold up to 32767 characters.
    std::string pfx;
    while (pfx.size() < 12000) {
        pfx += "MIIKXAIBAzCCChIGCSqGSIb3DQEHAaCCCgMEggn/+/==";
    }
    const rp::test::ScopedEnv env(rp::kEnvGraphCertPfxBase64, pfx);

    REQUIRE(rp::load_secrets_from_env().graph_cert_pfx_base64 == pfx);
}

TEST_CASE("load_secrets_from_env reads a value outside the ANSI code page as UTF-8", "[secrets]")
{
    // Cyrillic zhe (U+0436) isn't in cp1252; the euro sign (U+20AC)
    // is 0x80 in cp1252, so a narrow read would return it unconverted.
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, L"p\u0436ss\u20AC");

    REQUIRE(rp::load_secrets_from_env().veeam_password == "p\xD0\xB6ss\xE2\x82\xAC");
}

TEST_CASE("load_secrets_from_env rejects a value that isn't valid Unicode, without showing it",
          "[secrets]")
{
    const std::string_view name = GENERATE(rp::kEnvVeeamUsername, rp::kEnvVeeamPassword,
                                           rp::kEnvGraphCertPfxBase64, rp::kEnvGraphCertPassword);
    CAPTURE(name);
    // An unpaired surrogate: no UTF-8 string holds it, so any conversion would
    // change the secret.
    const rp::test::ScopedEnv env(name, std::wstring{L"SENTINEL-c2e0"} + L'\xD800');

    try {
        rp::load_secrets_from_env();
        FAIL("load_secrets_from_env accepted an unpaired surrogate");
    } catch (const rp::ConfigError& e) {
        REQUIRE(e.key() == name);
        REQUIRE(std::string{e.what()} ==
                "environment variable " + std::string{name} + " is not valid Unicode");
    }
}

TEST_CASE("ScopedEnv sets and reads back a value outside the ANSI code page", "[secrets]")
{
    const std::string name = "RP_TEST_SCOPED_ENV_4a90";
    const rp::test::ScopedEnv env(name, "p\xD0\xB6ss\xE2\x82\xAC");

    REQUIRE(rp::test::get_env(name) == "p\xD0\xB6ss\xE2\x82\xAC");
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
