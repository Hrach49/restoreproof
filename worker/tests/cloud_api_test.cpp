// W5.1 (docs/decisions.md 2026-10-15, "W5.1 (#66)", points 2, 3 and 5): the
// contract header's rule, the token's shape, the registration's request and
// answer, state\worker.json. The answers are the Cloud's own, recorded from
// the Compose stack through Caddy (tests/fixtures/cloud/).

#include <rp/canonical_json.hpp>
#include <rp/cloud_api.hpp>

#include "fake_http_client.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <nlohmann/json.hpp>

#include <string>

using rp::CloudAnswerKind;
using rp::HttpResponse;
using rp::test::load_fixture;
using rp::test::load_fixture_json;
using rp::test::to_response;

namespace {

// A token of the Cloud's shape, never a real one.
const std::string kToken = "TestToken-w51-0123456789abcdefABCDEF_-01234";

// The recorded 201 with a token in the placeholder's place.
std::string registration_answer(const std::string& token = kToken)
{
    nlohmann::json fixture = load_fixture_json("cloud", "register/201");
    fixture["body"]["api_token"] = token;
    return to_response(fixture).body;
}

} // namespace

TEST_CASE("every recorded answer of the Cloud's app carries the contract header, a proxy's none",
          "[cloud]")
{
    // Caddy hands the name on as X-Restoreproof-Api: the name is read in any case.
    for (const char* name : {"register/201", "jobs/200-one-job", "jobs/200-none", "results/202",
                             "results/202-again", "heartbeat/204", "version/200"}) {
        CAPTURE(name);
        CHECK(rp::cloud_answer_kind(load_fixture("cloud", name)) == CloudAnswerKind::cloud);
    }
    for (const char* name : {"jobs/502-proxy", "results/502-proxy"}) {
        CAPTURE(name);
        CHECK(rp::cloud_answer_kind(load_fixture("cloud", name)) == CloudAnswerKind::not_cloud);
    }
}

TEST_CASE("the contract header is the value 1 exactly; another value is another contract",
          "[cloud]")
{
    const auto [value, kind, text] = GENERATE(table<std::string, CloudAnswerKind, std::string>({
        {"1", CloudAnswerKind::cloud, "1"},
        {"2", CloudAnswerKind::other_contract, "2"},
        {"123456789", CloudAnswerKind::other_contract, "123456789"},
        {"1234567890", CloudAnswerKind::other_contract, "another value"},
        {" 1", CloudAnswerKind::other_contract, "another value"},
        {"1 ", CloudAnswerKind::other_contract, "another value"},
        {"01", CloudAnswerKind::other_contract, "01"},
        {"", CloudAnswerKind::other_contract, "another value"},
        {"v1", CloudAnswerKind::other_contract, "another value"},
        {"1\r\nX-Evil: 1", CloudAnswerKind::other_contract, "another value"},
    }));
    CAPTURE(value);
    HttpResponse response;
    response.status = 202;
    response.headers["x-restoreproof-api"] = value;

    CHECK(rp::cloud_answer_kind(response) == kind);
    CHECK(rp::other_contract_text(response) == text);
}

TEST_CASE("an answer without the header names no value", "[cloud]")
{
    HttpResponse response;
    response.status = 200;
    CHECK(rp::cloud_answer_kind(response) == CloudAnswerKind::not_cloud);
    CHECK(rp::other_contract_text(response) == "another value");
}

TEST_CASE("the bearer header and the token's shape", "[cloud]")
{
    CHECK(rp::bearer(kToken) == "Bearer " + kToken);
    CHECK(rp::is_cloud_token(kToken));
    CHECK(rp::is_cloud_token(std::string(43, 'A')));
    for (const std::string& bad :
         {std::string{}, std::string(42, 'A'), std::string(44, 'A'), std::string(42, 'A') + "=",
          std::string(42, 'A') + "+", std::string(42, 'A') + "/", std::string(42, 'A') + " ",
          std::string(42, 'A') + "\xc3", std::string{"SCRUBBED"}}) {
        CAPTURE(bad);
        CHECK_FALSE(rp::is_cloud_token(bad));
    }
}

TEST_CASE("a worker name is 1 to 128 code points with no control character", "[cloud]")
{
    CHECK(rp::is_worker_name("VEEAM-LAB01"));
    CHECK(rp::is_worker_name("veeam-01.contoso.local"));
    CHECK(rp::is_worker_name(std::string(128, 'n')));
    // 128 code points of two bytes each.
    std::string wide;
    for (int i = 0; i < 128; ++i) {
        wide += "\xc3\xa9";
    }
    CHECK(rp::is_worker_name(wide));
    for (const std::string& bad :
         {std::string{}, std::string(129, 'n'), wide + "e", std::string{"a\tb"}, std::string{"a\nb"},
          std::string{"a\x7f"}, std::string{"a\xc2\x85"}, std::string{"a\x00b", 3},
          std::string{"\xff"}, std::string{"a\xc3"}}) {
        CAPTURE(bad);
        CHECK_FALSE(rp::is_worker_name(bad));
    }
}

TEST_CASE("the registration's body is canonical JSON of the four keys the Cloud takes", "[cloud]")
{
    const std::string pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n";
    const std::string body = rp::registration_body(kToken, pem, "VEEAM-LAB01", "0.0.0");

    const nlohmann::json parsed = nlohmann::json::parse(body);
    CHECK(body == rp::canonical_json(parsed));
    CHECK(parsed == nlohmann::json{{"install_token", kToken},
                                   {"public_key_pem", pem},
                                   {"version", "0.0.0"},
                                   {"worker_name", "VEEAM-LAB01"}});
    CHECK_THROWS_AS(rp::registration_body(kToken, pem, "\xff", "0.0.0"), rp::CanonicalJsonError);
}

TEST_CASE("the Cloud's 201 is read as its three values", "[cloud]")
{
    const std::optional<rp::Registration> read = rp::parse_registration(registration_answer());

    REQUIRE(read);
    CHECK(read->worker_id == "65fddc39-0792-4178-8361-49d53450b29e");
    CHECK(read->api_token == kToken);
    CHECK(read->key_id == "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9");
}

TEST_CASE("an answer that isn't exactly the 201's shape is no registration", "[cloud]")
{
    const nlohmann::json good = nlohmann::json::parse(registration_answer());
    std::vector<std::string> texts;
    const auto with = [&good](const std::string& key, const nlohmann::json& value) {
        nlohmann::json changed = good;
        changed[key] = value;
        return changed.dump();
    };
    const auto without = [&good](const std::string& key) {
        nlohmann::json changed = good;
        changed.erase(key);
        return changed.dump();
    };
    texts.push_back("");
    texts.push_back("not json");
    texts.push_back("[]");
    texts.push_back("null");
    texts.push_back(R"({"worker_id":"65fddc39-0792-4178-8361-49d53450b29e","worker_id":"x"})");
    texts.push_back(without("worker_id"));
    texts.push_back(without("api_token"));
    texts.push_back(without("key_id"));
    texts.push_back(with("extra", 1));
    texts.push_back(with("worker_id", 1));
    texts.push_back(with("worker_id", "65fddc39"));
    texts.push_back(with("api_token", "SCRUBBED"));
    texts.push_back(with("api_token", nullptr));
    texts.push_back(with("key_id", std::string(64, 'A')));
    texts.push_back(with("key_id", std::string(63, 'a')));
    texts.push_back(with("key_id", std::string(64, 'g')));
    texts.push_back(with("key_id", 7));
    // Deeper than the strict reader ever parses.
    texts.push_back(std::string(1000, '[') + std::string(1000, ']'));
    for (const std::string& text : texts) {
        CAPTURE(text.substr(0, 80));
        CHECK_FALSE(rp::parse_registration(text));
    }
}

TEST_CASE("state\\worker.json is canonical JSON and reads back; anything else is no record",
          "[cloud]")
{
    const rp::WorkerRecord record{"65fddc39-0792-4178-8361-49d53450b29e",
                                  "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9",
                                  "https://localhost:8443", "2026-10-15T12:40:20Z"};
    const std::string text = rp::worker_record_text(record);

    CHECK(text == R"({"cloud_url":"https://localhost:8443","format":"restoreproof.worker.v1",)"
                  R"("key_id":"06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9",)"
                  R"("registered_at":"2026-10-15T12:40:20Z",)"
                  R"("worker_id":"65fddc39-0792-4178-8361-49d53450b29e"})");
    const std::optional<rp::WorkerRecord> back = rp::parse_worker_record(text);
    REQUIRE(back);
    CHECK(back->worker_id == record.worker_id);
    CHECK(back->key_id == record.key_id);
    CHECK(back->cloud_url == record.cloud_url);
    CHECK(back->registered_at == record.registered_at);

    const nlohmann::json good = nlohmann::json::parse(text);
    const auto with = [&good](const std::string& key, const nlohmann::json& value) {
        nlohmann::json changed = good;
        changed[key] = value;
        return rp::canonical_json(changed);
    };
    for (const std::string& bad :
         {std::string{}, std::string{"{}"}, good.dump(2), with("format", "restoreproof.worker.v2"),
          with("worker_id", "x"), with("key_id", "ABC"), with("cloud_url", 1),
          with("registered_at", "2026-10-15 12:40:20"), with("extra", true),
          std::string{"not json"}}) {
        CAPTURE(bad.substr(0, 80));
        CHECK_FALSE(rp::parse_worker_record(bad));
    }
}

TEST_CASE("a worker name counts a character outside the BMP once", "[cloud]")
{
    // U+1F600, a surrogate pair in UTF-16: one code point of the 128.
    std::string smiles;
    for (int i = 0; i < 128; ++i) {
        smiles += "\xF0\x9F\x98\x80";
    }
    CHECK(rp::is_worker_name(smiles));
    CHECK_FALSE(rp::is_worker_name(smiles + "a"));
}
