// One test per third-party dependency from worker/vcpkg.json: each proves the
// package is found, its headers compile and its library links and runs. No
// network access.

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>
#include <zip.h>

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

TEST_CASE("cpr builds a session URL with encoded query parameters without a network call", "[deps]")
{
    cpr::Session session;
    session.SetUrl(cpr::Url{"https://veeam.invalid/v8/Organizations"});
    session.SetParameters(cpr::Parameters{{"name", "restore test"}, {"limit", "10"}});

    // The query string is URL-encoded by libcurl, so this also proves curl is
    // linked. GetFullRequestUrl only builds the URL; nothing is sent.
    REQUIRE(session.GetFullRequestUrl() ==
            "https://veeam.invalid/v8/Organizations?name=restore%20test&limit=10");
}

TEST_CASE("libzip writes a deflated entry into memory and reads it back", "[deps]")
{
    // office-v1 (rp/office_v1.hpp) reads restored packages from memory the
    // same way; built without bzip2 or AES, deflate comes from zlib.
    zip_error_t error;
    zip_error_init(&error);
    zip_source_t* buffer = zip_source_buffer_create(nullptr, 0, 0, &error);
    REQUIRE(buffer != nullptr);
    zip_source_keep(buffer);  // outlives the first archive, so it can be reopened

    zip_t* archive = zip_open_from_source(buffer, ZIP_TRUNCATE, &error);
    REQUIRE(archive != nullptr);
    const std::string text(1000, 'w');
    zip_source_t* data = zip_source_buffer(archive, text.data(), text.size(), 0);
    REQUIRE(data != nullptr);
    REQUIRE(zip_file_add(archive, "word/document.xml", data, ZIP_FL_ENC_UTF_8) == 0);
    REQUIRE(zip_close(archive) == 0);

    archive = zip_open_from_source(buffer, ZIP_RDONLY | ZIP_CHECKCONS, &error);
    REQUIRE(archive != nullptr);
    zip_stat_t stat;
    REQUIRE(zip_stat(archive, "word/document.xml", 0, &stat) == 0);
    CHECK(stat.comp_method == ZIP_CM_DEFLATE);
    CHECK(stat.comp_size < stat.size);
    zip_file_t* file = zip_fopen(archive, "word/document.xml", 0);
    REQUIRE(file != nullptr);
    std::string read(2000, '\0');
    const zip_int64_t got = zip_fread(file, read.data(), read.size());
    zip_fclose(file);
    zip_discard(archive);  // frees the buffer too
    zip_error_fini(&error);
    REQUIRE(got == 1000);
    read.resize(1000);
    CHECK(read == text);
}
