#include <rp/config.hpp>
#include <rp/secrets.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

TEST_CASE("the secrets are the five documented names, the vault's (W4.5)", "[secrets]")
{
    // The Graph app signs in with a certificate, not a client secret (W2.1);
    // the signing key is the last (W4.3). No RP_* variable since W4.5.
    REQUIRE(rp::kSecretNames.size() == 5);
    REQUIRE(rp::kSecretNames[0] == "veeam_username");
    REQUIRE(rp::kSecretNames[1] == "veeam_password");
    REQUIRE(rp::kSecretNames[2] == "graph_cert_pfx_base64");
    REQUIRE(rp::kSecretNames[3] == "graph_cert_password");
    REQUIRE(rp::kSecretNames[4] == "signing_key_base64");
    REQUIRE(rp::kNameSigningKeyBase64 == "signing_key_base64");
    for (const std::string_view name : rp::kSecretNames) {
        CAPTURE(name);
        REQUIRE_FALSE(name.starts_with("RP_"));
    }
}

TEST_CASE("not_in_vault is one fixed sentence naming the secret", "[secrets]")
{
    REQUIRE(rp::not_in_vault("veeam_username") == "veeam_username is not in the vault");
    REQUIRE(rp::not_in_vault(rp::kNameSigningKeyBase64) ==
            "signing_key_base64 is not in the vault");
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

TEST_CASE("require_veeam_secrets names the first Veeam secret that is unset or empty",
          "[secrets]")
{
    using Secret = std::optional<std::string>;
    const auto [username, password, name] = GENERATE(table<Secret, Secret, std::string>({
        {std::nullopt, "p", "veeam_username"},
        {std::string{}, "p", "veeam_username"},
        {std::nullopt, std::nullopt, "veeam_username"},
        {"u", std::nullopt, "veeam_password"},
        {"u", std::string{}, "veeam_password"},
    }));
    const rp::Secrets secrets{username, password, std::nullopt, std::nullopt};

    try {
        rp::require_veeam_secrets(secrets);
        FAIL("require_veeam_secrets did not throw");
    } catch (const rp::ConfigError& e) {
        CHECK(e.key() == name);
        CHECK(std::string{e.what()} == name + " is not in the vault");
    }
}

TEST_CASE("require_veeam_secrets accepts both Veeam secrets set, whatever the Graph ones",
          "[secrets]")
{
    CHECK_NOTHROW(rp::require_veeam_secrets(rp::Secrets{"u", "p", std::nullopt, std::nullopt}));
}

TEST_CASE("secret_values gives each set secret value as it is, the user name never", "[secrets]")
{
    SECTION("all set: the password, the PFX, its password and the signing key's text")
    {
        const rp::Secrets secrets{"rp-veeam", "pw-71c0", "pfx-71c0", "pfx-pw-71c0", "key-71c0"};

        CHECK(rp::secret_values(secrets) ==
              std::vector<std::string>{"pw-71c0", "pfx-71c0", "pfx-pw-71c0", "key-71c0"});
    }
    SECTION("an unset or empty one is left out")
    {
        const rp::Secrets secrets{"rp-veeam", std::nullopt, std::string{}, "pfx-pw-71c0",
                                  std::nullopt};

        CHECK(rp::secret_values(secrets) == std::vector<std::string>{"pfx-pw-71c0"});
    }
    SECTION("none set")
    {
        CHECK(rp::secret_values(rp::Secrets{}).empty());
    }
    SECTION("a signing key that is no key is still a value: nothing is decoded")
    {
        rp::Secrets secrets;
        secrets.signing_key_base64 = "not base64 !!";

        CHECK(rp::secret_values(secrets) == std::vector<std::string>{"not base64 !!"});
    }
}

TEST_CASE("secret_values leaves room for what its caller adds, so no value moves", "[secrets]")
{
    // A value short enough to live inside its string object: a list that
    // grew would leave its bytes behind in the block it left, never wiped.
    const rp::Secrets secrets{"rp-veeam", "pw-71c0", "pfx-71c0", "pfx-pw-71c0", "key-71c0"};
    const std::size_t room = GENERATE(std::size_t{0}, std::size_t{3});

    std::vector<std::string> values = rp::secret_values(secrets, room);
    REQUIRE(values.size() == 4);
    const std::string* const first = values.data();
    const char* const first_bytes = values.front().data();
    for (std::size_t i = 0; i < room; ++i) {
        values.emplace_back("added");
    }

    CHECK(values.capacity() >= 4 + room);
    CHECK(values.data() == first);
    CHECK(values.front().data() == first_bytes);
}
