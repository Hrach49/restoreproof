#include <rp/config.hpp>

#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using nlohmann::json;

namespace {

// A config with every key set to a valid value.
json valid_doc()
{
    return json{
        {"cloud_url", "https://cloud.example.invalid"},
        {"veeam_url", "https://veeam.example.invalid:4443"},
        {"veeam_org_name", "example.onmicrosoft.com"},
        {"graph_tenant_id", "00000000-0000-0000-0000-000000000001"},
        {"graph_client_id", "00000000-0000-0000-0000-000000000002"},
        {"test_mailbox", "restoretest@example.onmicrosoft.com"},
        {"test_site_id", "site-id"},
        {"test_library_id", "library-id"},
        {"test_onedrive_drive_id", "drive-id"},
        {"test_onedrive_folder_id", "folder-id"},
        {"poll_interval_s", 60},
        {"heartbeat_interval_s", 120},
        {"sample_mail", 1},
        {"sample_sp", 2},
        {"sample_od", 3},
        {"log_level", "debug"},
    };
}

// A config with only the required keys.
json required_only_doc()
{
    json doc = valid_doc();
    for (const char* key : {"poll_interval_s", "heartbeat_interval_s", "sample_mail", "sample_sp",
                            "sample_od", "log_level"}) {
        doc.erase(key);
    }
    return doc;
}

// Parses `text`, expecting a ConfigError; returns it.
rp::ConfigError parse_error(const std::string& text)
{
    try {
        rp::parse_config(text);
    } catch (const rp::ConfigError& e) {
        return e;
    }
    FAIL("parse_config accepted: " << text);
    return rp::ConfigError("", "unreachable");
}

// A valid config whose sample_mail is `number`, written as is: for numbers
// json can't hold or would write differently.
std::string with_raw_sample_mail(const std::string& number)
{
    json doc = valid_doc();
    doc.erase("sample_mail");
    std::string text = doc.dump();
    text.pop_back();
    return text + ",\"sample_mail\":" + number + "}";
}

const std::vector<std::string> kRequiredKeys{
    "cloud_url",       "veeam_url",       "veeam_org_name",         "graph_tenant_id",
    "graph_client_id", "test_mailbox",    "test_site_id",           "test_library_id",
    "test_onedrive_drive_id", "test_onedrive_folder_id"};

const std::vector<std::string> kIntKeys{"poll_interval_s", "heartbeat_interval_s", "sample_mail",
                                        "sample_sp", "sample_od"};

} // namespace

TEST_CASE("ConfigError carries the offending key and the message", "[config]")
{
    const rp::ConfigError e("cloud_url", "config key \"cloud_url\" is missing (required)");
    REQUIRE(e.key() == "cloud_url");
    REQUIRE(std::string{e.what()} == "config key \"cloud_url\" is missing (required)");
}

TEST_CASE("parse_config rejects text that isn't JSON without quoting it", "[config]")
{
    // The last token nlohmann reads is the sentinel; its own message would quote it.
    const auto [text, byte] = GENERATE(table<std::string, std::string>({
        {"", "1"},
        {"   ", "4"},
        {"{\"cloud_url\": \"SENTINEL-4f1c", "29"},
        {"{\"cloud_url\": SENTINEL-4f1c}", "15"},
        {"{\"a\": 1,}", "9"},
    }));
    CAPTURE(text);

    const rp::ConfigError e = parse_error(text);
    REQUIRE(e.key().empty());
    REQUIRE(std::string{e.what()} == "config is not valid JSON (error at byte " + byte + ")");
    REQUIRE_THAT(e.what(), !ContainsSubstring("SENTINEL"));
}

TEST_CASE("parse_config rejects a number too large for a double without quoting it", "[config]")
{
    // nlohmann throws out_of_range (not parse_error) here, quoting the token.
    const std::string number = GENERATE("1e400", "-1e400", "1e99999");
    CAPTURE(number);
    const std::string text = with_raw_sample_mail(number);

    const rp::ConfigError e = parse_error(text);
    REQUIRE(e.key().empty());
    REQUIRE(std::string{e.what()} == "config is not valid JSON (a number is out of range)");
}

TEST_CASE("parse_config reports an integer too large for 64 bits as not an integer", "[config]")
{
    // nlohmann stores it as a double, so it isn't a JSON integer any more.
    const rp::ConfigError e = parse_error(with_raw_sample_mail("99999999999999999999"));
    REQUIRE(e.key() == "sample_mail");
    REQUIRE(std::string{e.what()} == "config key \"sample_mail\" must be an integer");
}

TEST_CASE("parse_config rejects a root that isn't an object", "[config]")
{
    const std::string text = GENERATE("[]", "[{\"cloud_url\": \"x\"}]", "\"text\"", "42", "null",
                                      "true");
    CAPTURE(text);

    const rp::ConfigError e = parse_error(text);
    REQUIRE(e.key().empty());
    REQUIRE(std::string{e.what()} == "config must be a JSON object");
}

TEST_CASE("parse_config rejects secret-looking keys without echoing the value", "[config]")
{
    const std::string key = GENERATE("password", "Password", "client_secret", "secret",
                                     "api_token", "TOKEN", "veeam_passwd", "api_key", "apikey",
                                     "Graph_Client_Secret", "pwd", "veeam_pwd", "credential",
                                     "Credentials", "private_key", "tls_private_key",
                                     "access_key", "AWS_ACCESS_KEY_ID", "signing_key",
                                     "connection_string", "Db_Connection_String");
    CAPTURE(key);
    json doc = valid_doc();
    doc[key] = "SENTINEL-8d2e";

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == key);
    REQUIRE(std::string{e.what()} ==
            "config key \"" + key +
                "\" looks like a secret; secrets don't belong in config.json. Set "
                "RP_VEEAM_USERNAME, RP_VEEAM_PASSWORD or RP_GRAPH_CLIENT_SECRET in the "
                "environment instead (they move to the DPAPI vault in W4.5)");
    REQUIRE_THAT(e.what(), !ContainsSubstring("SENTINEL"));
}

TEST_CASE("none of the 16 known keys looks like a secret", "[config]")
{
    // valid_doc() sets all 16; it parses only if none trips the secret check.
    const json doc = valid_doc();
    REQUIRE(doc.size() == 16);
    REQUIRE_NOTHROW(rp::parse_config(doc.dump()));
}

TEST_CASE("parse_config reports a secret-looking key before a missing required key", "[config]")
{
    json doc = valid_doc();
    doc.erase("cloud_url");
    doc["veeam_password"] = "SENTINEL-8d2e";

    REQUIRE(parse_error(doc.dump()).key() == "veeam_password");
}

TEST_CASE("parse_config reports a secret-looking key before an unknown key", "[config]")
{
    // Keys are checked in name order, so the unknown one comes first.
    json doc = valid_doc();
    doc["aaa_unknown"] = "value";
    doc["zzz_password"] = "SENTINEL-8d2e";

    REQUIRE(parse_error(doc.dump()).key() == "zzz_password");
}

TEST_CASE("parse_config reports an unknown key before a missing required key", "[config]")
{
    json doc = valid_doc();
    doc.erase("cloud_url");
    doc["zzz_unknown"] = "value";

    REQUIRE(parse_error(doc.dump()).key() == "zzz_unknown");
}

TEST_CASE("parse_config rejects unknown keys, case-sensitively", "[config]")
{
    const std::string key = GENERATE(std::string("cloud_uri"), "Cloud_Url", "LOG_LEVEL",
                                     "sample_size", "a.b-c_9", "x", std::string(64, 'k'));
    CAPTURE(key);
    json doc = valid_doc();
    doc[key] = "value";

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == key);
    REQUIRE(std::string{e.what()} == "config key \"" + key + "\" is not a known setting");
}

// Key names that could be a pasted secret, forge output lines or flood it.
const std::vector<std::string> kUnprintableKeys{
    "",
    "SENTINEL-6c0a\nconfig file: forged",
    "SENTINEL-6c0a\x1b[2J",
    "log level",
    "SENTINEL-6c0a\"",
    "caf\xc3\xa9",
    std::string(65, 'k'),
    std::string(200000, 'k'),
};

TEST_CASE("parse_config rejects an unknown key without printing an unsafe name", "[config]")
{
    const std::string key = GENERATE_REF(from_range(kUnprintableKeys));
    CAPTURE(key.size());
    json doc = valid_doc();
    doc[key] = "value";

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key().empty());
    REQUIRE(std::string{e.what()} ==
            "config has a key that is not a known setting (its name isn't shown: only 1-64 "
            "letters, digits, '_', '.' and '-' are printed)");
}

TEST_CASE("parse_config rejects a secret-looking key without printing an unsafe name",
          "[config]")
{
    const std::string key = GENERATE(std::string("SENTINEL-6c0a\npassword"), "my password",
                                     "password" + std::string(57, 'k'),
                                     "token\x1b[2J");
    CAPTURE(key.size());
    json doc = valid_doc();
    doc[key] = "SENTINEL-6c0a";

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key().empty());
    REQUIRE(std::string{e.what()} ==
            "config has a key that looks like a secret; secrets don't belong in config.json. Set "
            "RP_VEEAM_USERNAME, RP_VEEAM_PASSWORD or RP_GRAPH_CLIENT_SECRET in the environment "
            "instead (they move to the DPAPI vault in W4.5)");
}

TEST_CASE("parse_config prints a secret-looking key of 64 safe characters", "[config]")
{
    const std::string key = "password" + std::string(56, 'k');
    json doc = valid_doc();
    doc[key] = "SENTINEL-6c0a";

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == key);
    REQUIRE_THAT(e.what(), ContainsSubstring("config key \"" + key + "\" looks like a secret"));
    REQUIRE_THAT(e.what(), !ContainsSubstring("SENTINEL"));
}

TEST_CASE("parse_config rejects a config missing a required key", "[config]")
{
    const std::string key = GENERATE_REF(from_range(kRequiredKeys));
    CAPTURE(key);
    json doc = valid_doc();
    doc.erase(key);

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == key);
    REQUIRE(std::string{e.what()} == "config key \"" + key + "\" is missing (required)");
}

TEST_CASE("parse_config rejects a string setting of the wrong JSON type", "[config]")
{
    std::vector<std::string> keys = kRequiredKeys;
    keys.push_back("log_level");
    const std::string key = GENERATE_REF(from_range(keys));
    const json value = GENERATE(json(1), json(true), json(nullptr), json::array(),
                                json::object(), json(1.5));
    CAPTURE(key, value.dump());
    json doc = valid_doc();
    doc[key] = value;

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == key);
    REQUIRE(std::string{e.what()} == "config key \"" + key + "\" must be a string");
}

TEST_CASE("parse_config rejects an integer setting of the wrong JSON type", "[config]")
{
    const std::string key = GENERATE_REF(from_range(kIntKeys));
    const json value = GENERATE(json("300"), json(3.5), json(5.0), json(true), json(nullptr),
                                json::array(), json::object());
    CAPTURE(key, value.dump());
    json doc = valid_doc();
    doc[key] = value;

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == key);
    REQUIRE(std::string{e.what()} == "config key \"" + key + "\" must be an integer");
}

TEST_CASE("parse_config rejects invalid values without echoing them", "[config]")
{
    const std::string interval = "must be an integer from 1 to 86400 (seconds)";
    const std::string sample = "must be an integer from 0 to 100";
    const std::string url = "must be an https:// URL with no user name, password, query or fragment";
    const std::string control = "must not contain control characters";
    const auto [key, value, rule] = GENERATE_COPY(table<std::string, json, std::string>({
        {"cloud_url", json(""), "must not be empty"},
        {"veeam_org_name", json(""), "must not be empty"},
        {"graph_tenant_id", json(""), "must not be empty"},
        {"graph_client_id", json(""), "must not be empty"},
        {"test_site_id", json(""), "must not be empty"},
        {"test_library_id", json(""), "must not be empty"},
        {"test_onedrive_drive_id", json(""), "must not be empty"},
        {"test_onedrive_folder_id", json(""), "must not be empty"},
        {"test_mailbox", json(""), "must not be empty"},
        {"log_level", json(""), "must not be empty"},
        // Checked before the rule, so a URL with a control character says so.
        {"cloud_url", json("https://cloud.example.invalid\n"), control},
        {"veeam_url", json("https://veeam.example.invalid\r"), control},
        {"veeam_org_name", json("example\tonmicrosoft.com"), control},
        {"graph_tenant_id", json("\x1b[2J"), control},
        {"graph_client_id", json("client\x7f"), control},
        {"test_mailbox", json("restoretest@example.invalid\n"), control},
        {"test_site_id", json(std::string("site\0id", 7)), control},
        {"test_library_id", json("\x01"), control},
        {"test_onedrive_drive_id", json("drive\x1f"), control},
        {"test_onedrive_folder_id", json("folder\n"), control},
        {"log_level", json("info\n"), control},
        // Non-ASCII controls, as UTF-8: C1 (U+0080-U+009F), line and paragraph
        // separators (U+2028, U+2029), bidi marks and overrides (U+200E, U+200F,
        // U+202A-U+202E), isolates (U+2066-U+2069) and the Arabic letter mark
        // (U+061C). Each row pins a boundary.
        {"veeam_org_name", json("example\xC2\x80"), control},
        {"veeam_org_name", json("example\xC2\x9F"), control},
        {"graph_tenant_id", json("tenant\xE2\x80\xA8"), control},
        {"graph_tenant_id", json("tenant\xE2\x80\xA9"), control},
        {"graph_client_id", json("client\xE2\x80\x8E"), control},
        {"graph_client_id", json("client\xE2\x80\x8F"), control},
        {"test_site_id", json("site\xE2\x80\xAA"), control},
        {"test_site_id", json("site\xE2\x80\xAE"), control},
        {"test_library_id", json("library\xE2\x81\xA6"), control},
        {"test_library_id", json("library\xE2\x81\xA9"), control},
        {"test_onedrive_folder_id", json("folder\xD8\x9C"), control},
        {"test_mailbox", json("\xE2\x80\xAE" "moc.elpmaxe@tset"), control},
        {"cloud_url", json("https://cloud.example.invalid\xC2\x85"), control},
        {"log_level", json("info\xE2\x80\xA8"), control},
        {"cloud_url", json("http://cloud.example.invalid"), url},
        {"cloud_url", json("ftp://cloud.example.invalid"), url},
        {"cloud_url", json("cloud.example.invalid"), url},
        {"cloud_url", json("https://"), url},
        {"cloud_url", json("https:///"), url},
        {"cloud_url", json(" https://cloud.example.invalid"), url},
        {"veeam_url", json("http://veeam.example.invalid:4443"), url},
        {"veeam_url", json("https:"), url},
        {"cloud_url", json("https://user:SENTINEL-e41b@cloud.example.invalid"), url},
        {"cloud_url", json("https://user@cloud.example.invalid"), url},
        {"cloud_url", json("https://@cloud.example.invalid/"), url},
        {"cloud_url", json("https://cloud.example.invalid:SENTINEL-e41b@x/path"), url},
        {"cloud_url", json("https://cloud.example.invalid/?token=SENTINEL-e41b"), url},
        {"cloud_url", json("https://cloud.example.invalid?token=SENTINEL-e41b"), url},
        {"cloud_url", json("https://cloud.example.invalid#SENTINEL-e41b"), url},
        {"veeam_url", json("https://veeam.example.invalid:4443/v8#x"), url},
        {"veeam_url", json("https://veeam.example.invalid:4443/v8?"), url},
        // URLs are printable ASCII only: a fullwidth @ (U+FF20) must not hide
        // userinfo, and non-ASCII or space can't appear either.
        {"cloud_url", json("https://u:SENTINEL-e41b\xEF\xBC\xA0" "cloud.example.invalid"), url},
        {"cloud_url", json("https://z\xC3\xBC" "rich.example.invalid"), url},
        {"cloud_url", json("https://\xC2\xA0" "cloud.example.invalid"), url},
        {"veeam_url", json("https://veeam example.invalid"), url},
        {"test_mailbox", json("restoretest"), "must be an email address"},
        {"test_mailbox", json("@example.invalid"), "must be an email address"},
        {"test_mailbox", json("restoretest@"), "must be an email address"},
        {"test_mailbox", json("@"), "must be an email address"},
        {"poll_interval_s", json(0), interval},
        {"poll_interval_s", json(-1), interval},
        {"poll_interval_s", json(86401), interval},
        {"poll_interval_s", json(1000000000000LL), interval},
        {"poll_interval_s", json(std::numeric_limits<std::int64_t>::max()), interval},
        {"poll_interval_s", json(std::numeric_limits<std::int64_t>::min()), interval},
        {"poll_interval_s", json(std::numeric_limits<std::uint64_t>::max()), interval},
        {"heartbeat_interval_s", json(0), interval},
        {"heartbeat_interval_s", json(86401), interval},
        {"heartbeat_interval_s", json(4294967297LL), interval},
        {"sample_mail", json(-1), sample},
        {"sample_mail", json(101), sample},
        {"sample_sp", json(-1), sample},
        {"sample_sp", json(101), sample},
        {"sample_od", json(-1), sample},
        {"sample_od", json(101), sample},
        {"sample_od", json(std::numeric_limits<std::uint64_t>::max()), sample},
        {"log_level", json("INFO"), "must be one of trace, debug, info, warn, error, critical, off"},
        {"log_level", json("warning"), "must be one of trace, debug, info, warn, error, critical, off"},
        {"log_level", json("info "), "must be one of trace, debug, info, warn, error, critical, off"},
    }));
    CAPTURE(key, value.dump());
    json doc = valid_doc();
    doc[key] = value;

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == key);
    // An exact match also proves the value isn't echoed.
    REQUIRE(std::string{e.what()} == "config key \"" + key + "\" " + rule);
}

TEST_CASE("parse_config checks fields in declaration order", "[config]")
{
    json doc = valid_doc();
    doc["sample_mail"] = 101;
    doc["test_mailbox"] = "no-at-sign";
    doc.erase("veeam_url");

    REQUIRE(parse_error(doc.dump()).key() == "veeam_url");
}

TEST_CASE("parse_config rejects a config that samples nothing", "[config]")
{
    json doc = valid_doc();
    doc["sample_mail"] = 0;
    doc["sample_sp"] = 0;
    doc["sample_od"] = 0;

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key().empty());
    REQUIRE(std::string{e.what()} == "config keys \"sample_mail\", \"sample_sp\" and \"sample_od\" "
                                     "are all 0; at least one must be above 0");
}

TEST_CASE("parse_config accepts boundary and edge values", "[config]")
{
    const auto [key, value] = GENERATE(table<std::string, json>({
        {"cloud_url", json("HTTPS://x")},
        {"cloud_url", json("Https://cloud.example.invalid/path/")},
        {"veeam_url", json("https://10.0.0.5:4443")},
        {"veeam_url", json("https://veeam.example.invalid:4443/v8/a@b")},
        {"test_mailbox", json("a@b")},
        // Non-ASCII UTF-8 bytes are above 0x7F, not control characters.
        {"test_mailbox", json("caf\xc3\xa9@example.invalid")},
        {"test_mailbox", json("Z\xC3\xBC" "rich@example.invalid")},
        {"test_mailbox", json("\xE6\x9D\xB1\xE4\xBA\xAC@example.invalid")},
        // Just outside the rejected ranges: U+00A0, U+061B, U+061D, U+200D, U+2027,
        // U+202F, U+2065, U+206A.
        {"test_mailbox", json("a\xC2\xA0" "b@example.invalid")},
        {"test_mailbox", json("a\xD8\x9B" "b@example.invalid")},
        {"test_mailbox", json("a\xD8\x9D" "b@example.invalid")},
        {"test_mailbox", json("a\xE2\x80\x8D" "b@example.invalid")},
        {"test_mailbox", json("a\xE2\x80\xA7" "b@example.invalid")},
        {"test_mailbox", json("a\xE2\x80\xAF" "b@example.invalid")},
        {"test_mailbox", json("a\xE2\x81\xA5" "b@example.invalid")},
        {"test_mailbox", json("a\xE2\x81\xAA" "b@example.invalid")},
        {"poll_interval_s", json(1)},
        {"poll_interval_s", json(86400)},
        {"heartbeat_interval_s", json(1)},
        {"heartbeat_interval_s", json(86400)},
        {"sample_mail", json(0)},
        {"sample_mail", json(100)},
        {"sample_sp", json(0)},
        {"sample_od", json(100)},
        {"log_level", json("trace")},
        {"log_level", json("debug")},
        {"log_level", json("info")},
        {"log_level", json("warn")},
        {"log_level", json("error")},
        {"log_level", json("critical")},
        {"log_level", json("off")},
    }));
    CAPTURE(key, value.dump());
    json doc = valid_doc();
    doc[key] = value;

    const rp::Config config = rp::parse_config(doc.dump());
    const json parsed{
        {"cloud_url", config.cloud_url},
        {"veeam_url", config.veeam_url},
        {"test_mailbox", config.test_mailbox},
        {"poll_interval_s", config.poll_interval_s},
        {"heartbeat_interval_s", config.heartbeat_interval_s},
        {"sample_mail", config.sample_mail},
        {"sample_sp", config.sample_sp},
        {"sample_od", config.sample_od},
        {"log_level", config.log_level},
    };
    REQUIRE(parsed.at(key) == value);
}

TEST_CASE("parse_config reads every key", "[config]")
{
    const rp::Config config = rp::parse_config(valid_doc().dump(2));

    REQUIRE(config.cloud_url == "https://cloud.example.invalid");
    REQUIRE(config.veeam_url == "https://veeam.example.invalid:4443");
    REQUIRE(config.veeam_org_name == "example.onmicrosoft.com");
    REQUIRE(config.graph_tenant_id == "00000000-0000-0000-0000-000000000001");
    REQUIRE(config.graph_client_id == "00000000-0000-0000-0000-000000000002");
    REQUIRE(config.test_mailbox == "restoretest@example.onmicrosoft.com");
    REQUIRE(config.test_site_id == "site-id");
    REQUIRE(config.test_library_id == "library-id");
    REQUIRE(config.test_onedrive_drive_id == "drive-id");
    REQUIRE(config.test_onedrive_folder_id == "folder-id");
    REQUIRE(config.poll_interval_s == 60);
    REQUIRE(config.heartbeat_interval_s == 120);
    REQUIRE(config.sample_mail == 1);
    REQUIRE(config.sample_sp == 2);
    REQUIRE(config.sample_od == 3);
    REQUIRE(config.log_level == "debug");
}

TEST_CASE("parse_config fills in defaults for absent optional keys", "[config]")
{
    const rp::Config config = rp::parse_config(required_only_doc().dump());

    REQUIRE(config.poll_interval_s == 300);
    REQUIRE(config.heartbeat_interval_s == 900);
    REQUIRE(config.sample_mail == 5);
    REQUIRE(config.sample_sp == 5);
    REQUIRE(config.sample_od == 5);
    REQUIRE(config.log_level == "info");
}

namespace {

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

// load_config(path), expecting a ConfigError; returns it.
rp::ConfigError load_error(const std::filesystem::path& path)
{
    try {
        rp::load_config(path);
    } catch (const rp::ConfigError& e) {
        return e;
    }
    FAIL("load_config accepted " << utf8(path));
    return rp::ConfigError("", "unreachable");
}

std::string lower(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

} // namespace

TEST_CASE("load_config reports a file it can't read, with the path", "[config]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path path = GENERATE_REF(dir.path() / "missing.json", dir.path());
    CAPTURE(utf8(path));

    const rp::ConfigError e = load_error(path);
    REQUIRE(e.key().empty());
    REQUIRE(std::string{e.what()} == utf8(path) + ": cannot read config file");
}

TEST_CASE("load_config prefixes validation errors with the path and keeps the key", "[config]")
{
    const rp::test::TempDir dir;
    json doc = valid_doc();
    doc.erase("test_mailbox");
    const auto path = dir.write("config.json", doc.dump());

    const rp::ConfigError e = load_error(path);
    REQUIRE(e.key() == "test_mailbox");
    REQUIRE(std::string{e.what()} ==
            utf8(path) + ": config key \"test_mailbox\" is missing (required)");
}

TEST_CASE("load_config reports an empty file as invalid JSON", "[config]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", "");

    REQUIRE(std::string{load_error(path).what()} ==
            utf8(path) + ": config is not valid JSON (error at byte 1)");
}

TEST_CASE("load_config handles a non-ASCII path", "[config]")
{
    const rp::test::TempDir dir;
    const auto path = dir.path() / std::filesystem::path(u8"r\u00e9sum\u00e9.json");

    const std::string message = load_error(path).what();
    REQUIRE(message == utf8(path) + ": cannot read config file");
    REQUIRE_THAT(message, ContainsSubstring("r\xc3\xa9sum\xc3\xa9.json: "));
}

TEST_CASE("load_config reads a valid file", "[config]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", valid_doc().dump(4));

    REQUIRE(rp::load_config(path).sample_od == 3);
}

TEST_CASE("load_config accepts a UTF-8 byte order mark, as Notepad writes", "[config]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", "\xEF\xBB\xBF" + valid_doc().dump(4));

    REQUIRE(rp::load_config(path).cloud_url == "https://cloud.example.invalid");
}

TEST_CASE("program_data_dir is the absolute ProgramData folder", "[config]")
{
    const std::filesystem::path dir = rp::program_data_dir();
    REQUIRE(dir.is_absolute());
    if (const auto env = rp::test::get_env("ProgramData")) {
        REQUIRE(lower(utf8(dir)) == lower(*env));
    }
}

TEST_CASE("default_config_path is config.json in RestoreProof under ProgramData", "[config]")
{
    const std::filesystem::path path = rp::default_config_path();
    REQUIRE(path.filename() == "config.json");
    REQUIRE(path.parent_path().filename() == "RestoreProof");
    REQUIRE(path.parent_path().parent_path() == rp::program_data_dir());
    REQUIRE(utf8(path).ends_with("\\RestoreProof\\config.json"));
}

TEST_CASE("config.example.json is a valid config of placeholders", "[config]")
{
    // RP_CONFIG_EXAMPLE is set by CMakeLists.txt, so the example can't rot.
    const rp::Config config = rp::load_config(std::filesystem::path(RP_CONFIG_EXAMPLE));

    REQUIRE_THAT(config.cloud_url, ContainsSubstring(".example.invalid"));
    REQUIRE_THAT(config.veeam_url, ContainsSubstring(".example.invalid"));
    REQUIRE(config.graph_tenant_id == "00000000-0000-0000-0000-000000000000");
    REQUIRE(config.graph_client_id == "00000000-0000-0000-0000-000000000000");
    // It shows every optional key at its default.
    REQUIRE(config.poll_interval_s == 300);
    REQUIRE(config.heartbeat_interval_s == 900);
    REQUIRE(config.sample_mail == 5);
    REQUIRE(config.sample_sp == 5);
    REQUIRE(config.sample_od == 5);
    REQUIRE(config.log_level == "info");
}

TEST_CASE("config.example.json sets every key", "[config]")
{
    std::ifstream file(std::filesystem::path(RP_CONFIG_EXAMPLE));
    const json doc = json::parse(file);
    REQUIRE(doc.size() == 16);
}
