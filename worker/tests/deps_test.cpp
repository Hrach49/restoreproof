// One test per third-party dependency from worker/vcpkg.json: each proves the
// package is found, its headers compile and its library links and runs. No
// network access.

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>

TEST_CASE("nlohmann-json parses and dumps with sorted keys and no whitespace", "[deps]")
{
    // Sorted keys and no whitespace are what the canonical-JSON signing
    // contract needs (CLAUDE.md); nlohmann::json gives both by default.
    const auto doc = nlohmann::json::parse(R"({ "status": "pass", "items": 40 })");
    REQUIRE(doc.at("status") == "pass");
    REQUIRE(doc.at("items") == 40);
    REQUIRE(doc.dump() == R"({"items":40,"status":"pass"})");
}

TEST_CASE("spdlog writes a formatted message to an ostream sink", "[deps]")
{
    std::ostringstream out;
    auto sink = std::make_shared<spdlog::sinks::ostream_sink_st>(out);
    spdlog::logger logger{"deps_test", sink};
    logger.set_pattern("[%l] %v");

    logger.info("restored {} of {} items", 39, 40);

    REQUIRE(out.str().starts_with("[info] restored 39 of 40 items"));
}

TEST_CASE("OpenSSL computes the known SHA-256 digest of \"abc\"", "[deps]")
{
    // FIPS 180-2 test vector.
    constexpr std::string_view input = "abc";
    constexpr std::string_view expected =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    REQUIRE(EVP_Digest(input.data(), input.size(), digest.data(), &length, EVP_sha256(), nullptr) == 1);
    REQUIRE(length == 32);

    std::ostringstream hex;
    for (unsigned int i = 0; i < length; ++i) {
        hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    REQUIRE(hex.str() == expected);
}

TEST_CASE("cpr builds a session and URL-encodes through libcurl without a network call", "[deps]")
{
    cpr::Session session;
    session.SetUrl(cpr::Url{"https://veeam.invalid/v8/Organizations"});
    session.SetTimeout(cpr::Timeout{1000});

    // urlEncode calls into libcurl, so this also proves curl is linked.
    REQUIRE(std::string{cpr::util::urlEncode("restore test")} == "restore%20test");
}
