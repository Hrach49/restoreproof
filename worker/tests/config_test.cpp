#include <rp/config.hpp>
#include <rp/timestamper.hpp>

#include "test_certs.hpp"
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
#include <optional>
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
        {"test_site_id", "example.sharepoint.com,00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002"},
        {"test_library_id", "b!library-id"},
        {"test_onedrive_drive_id", "b!drive-id"},
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

// An absolute path for veeam_ca_file. parse_config never opens the file, so it
// needn't exist; the load_config tests use real ones.
const std::string kCaFile = "C:\\ProgramData\\RestoreProof\\veeam-ca.pem";

// A value for veeam_cert_sha256: the lab certificate's SHA-256, as Windows
// shows it. parse_config only checks its form.
const std::string kCertSha256 = "9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213";

std::string lower(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

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
                                     "connection_string", "Db_Connection_String",
                                     // The Graph certificate's PFX and its password (W2.1).
                                     "pfx", "graph_cert_pfx", "PFX_Base64",
                                     "rp_graph_cert_pfx_base64", "passphrase",
                                     "pfx_passphrase", "Key_Passphrase");
    CAPTURE(key);
    json doc = valid_doc();
    doc[key] = "SENTINEL-8d2e";

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == key);
    REQUIRE(std::string{e.what()} ==
            "config key \"" + key +
                "\" looks like a secret; secrets don't belong in config.json. Put it in the "
                "vault with rpworker vault set <name> instead (veeam_username, "
                "veeam_password, graph_cert_pfx_base64, graph_cert_password or "
                "signing_key_base64)");
    REQUIRE_THAT(e.what(), !ContainsSubstring("SENTINEL"));
}

TEST_CASE("none of the 19 known keys looks like a secret", "[config]")
{
    // valid_doc() sets the 16 that need no file; veeam_ca_file,
    // veeam_cert_sha256 and screenshots_enabled make 19. It parses only if
    // none trips the secret check.
    json doc = valid_doc();
    doc["veeam_ca_file"] = kCaFile;
    doc["veeam_cert_sha256"] = kCertSha256;
    doc["screenshots_enabled"] = true;
    REQUIRE(doc.size() == 19);
    REQUIRE_NOTHROW(rp::parse_config(doc.dump()));
}

TEST_CASE("a key naming a certificate is not taken for a secret", "[config]")
{
    // "cert" is not a secret marker: veeam_cert_sha256 is a setting, and a
    // certificate's thumbprint or path is public. Such keys are only unknown.
    const std::string key = GENERATE("graph_cert_thumbprint", "graph_cert_file", "cert",
                                     "Veeam_Cert_Path");
    CAPTURE(key);
    json doc = valid_doc();
    doc[key] = "value";

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == key);
    REQUIRE(std::string{e.what()} == "config key \"" + key + "\" is not a known setting");
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
                                     "sample_size", "a.b-c_9", "x", std::string(64, 'k'),
                                     "Veeam_CA_File", "veeam_ca", "ca_file",
                                     "Veeam_Cert_SHA256", "veeam_cert_sha1",
                                     "veeam_cert_thumbprint", "Screenshots_Enabled",
                                     "screenshot_enabled", "screenshots");
    CAPTURE(key);
    json doc = valid_doc();
    doc[key] = "value";

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == key);
    REQUIRE(std::string{e.what()} == "config key \"" + key + "\" is not a known setting");
}

TEST_CASE("parse_config has no key that turns TLS certificate verification off", "[config]")
{
    // veeam_ca_file only chooses what to trust; no setting skips verification.
    const std::string key = GENERATE("veeam_verify_tls", "verify_tls", "insecure",
                                     "veeam_insecure", "veeam_skip_tls_verify",
                                     "tls_insecure_skip_verify", "ssl_verify", "verify_ssl",
                                     "veeam_verify_ssl", "skip_verify");
    CAPTURE(key);
    json doc = valid_doc();
    doc[key] = false;

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
            "config has a key that looks like a secret; secrets don't belong in config.json. Put "
            "it in the vault with rpworker vault set <name> instead (veeam_username, "
            "veeam_password, graph_cert_pfx_base64, graph_cert_password or "
            "signing_key_base64)");
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
    keys.push_back("veeam_ca_file");
    keys.push_back("veeam_cert_sha256");
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
    const std::string guid =
        "must be a GUID (8-4-4-4-12 hexadecimal digits, as the Entra admin center shows it), "
        "not a name";
    const std::string mailbox =
        "must be restoretest@<domain>: restores only ever go to the restoretest mailbox";
    // Review of W2.2: the ID shapes are checked here, so `config check` catches them.
    const std::string site_rule =
        "must be a Graph site ID (\"<tenant>.sharepoint.com,<site GUID>,<web GUID>\")";
    const std::string drive_rule =
        "must be a Graph drive ID (\"b!\" then letters, digits, '-' and '_'), not a list ID";
    const std::string item_rule = "must be a Graph item ID (letters, digits, '!', '-' and '_')";
    const std::string g = "0a1b2c3d-0000-4000-8000-00000000abcd";
    const std::string absolute =
        "must be an absolute path, such as C:\\ProgramData\\RestoreProof\\veeam-ca.pem or "
        "\\\\server\\share\\veeam-ca.pem";
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
        {"graph_client_id", json("00000000-0000-0000-0000-000000000002\x7f"), control},
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
        {"graph_tenant_id", json("00000000-0000-0000-0000-000000000001\xE2\x80\xA8"), control},
        {"graph_tenant_id", json("00000000-0000-0000-0000-000000000001\xE2\x80\xA9"), control},
        {"graph_client_id", json("00000000-0000-0000-0000-000000000002\xE2\x80\x8E"), control},
        {"graph_client_id", json("\xE2\x80\x8F" "00000000-0000-0000-0000-000000000002"), control},
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
        {"test_library_id", json("x/children"), drive_rule},
        {"test_library_id", json("b!a?b"), drive_rule},
        {"test_library_id", json("b!a%2e"), drive_rule},
        {"test_library_id", json("b!"), drive_rule},
        {"test_library_id", json(g), drive_rule},
        {"test_library_id", json("b!" + std::string(201, 'a')), drive_rule},
        {"test_library_id", json("b!\xC3\xA9"), drive_rule},
        {"test_onedrive_drive_id", json("a/b"), drive_rule},
        {"test_onedrive_drive_id", json("b!a b"), drive_rule},
        {"test_onedrive_folder_id", json("a/b"), item_rule},
        {"test_onedrive_folder_id", json("a?b"), item_rule},
        {"test_onedrive_folder_id", json(std::string(201, 'a')), item_rule},
        {"test_site_id", json("host"), site_rule},
        {"test_site_id", json("h,notaguid,alsonot"), site_rule},
        {"test_site_id", json("evil.com," + g + "," + g), site_rule},
        {"test_site_id", json("a.b.sharepoint.com," + g + "," + g), site_rule},
        {"test_site_id", json(".sharepoint.com," + g + "," + g), site_rule},
        {"test_site_id", json("t.sharepoint.com," + g), site_rule},
        {"test_site_id", json("t.sharepoint.com," + g + "," + g + "," + g), site_rule},
        {"test_site_id", json("t.sharepoint.com," + g + ",x"), site_rule},
        {"test_site_id", json("t_x.sharepoint.com," + g + "," + g), site_rule},
        {"test_site_id", json(std::string(64, 't') + ".sharepoint.com," + g + "," + g), site_rule},
        {"test_mailbox", json("restoretest"), mailbox},
        {"test_mailbox", json("@example.invalid"), mailbox},
        {"test_mailbox", json("restoretest@"), mailbox},
        {"test_mailbox", json("@"), mailbox},
        // Any other mailbox could be a live one: restores only ever go to
        // restoretest (docs/decisions.md).
        {"test_mailbox", json("ceo@contoso.com"), mailbox},
        {"test_mailbox", json("restoretest2@example.invalid"), mailbox},
        {"test_mailbox", json("xrestoretest@example.invalid"), mailbox},
        {"test_mailbox", json("restore.test@example.invalid"), mailbox},
        {"test_mailbox", json(" restoretest@example.invalid"), mailbox},
        {"test_mailbox", json("restoretest@example.invalid "), mailbox},
        // One '@', then a domain of two or more dot-separated labels of ASCII
        // letters, digits and '-'.
        {"test_mailbox", json("restoretest@@example.invalid"), mailbox},
        {"test_mailbox", json("restoretest@a@example.invalid"), mailbox},
        {"test_mailbox", json("restoretest@example"), mailbox},
        {"test_mailbox", json("restoretest@.example.invalid"), mailbox},
        {"test_mailbox", json("restoretest@example..invalid"), mailbox},
        {"test_mailbox", json("restoretest@example.invalid."), mailbox},
        {"test_mailbox", json("restoretest@exa mple.invalid"), mailbox},
        {"test_mailbox", json("restoretest@exa_mple.invalid"), mailbox},
        // Look-alikes: a Cyrillic ie (U+0435) for the e, a fullwidth @ (U+FF20),
        // a zero-width space (U+200B), a non-ASCII domain.
        {"test_mailbox", json("restor\xD0\xB5test@example.invalid"), mailbox},
        {"test_mailbox", json("restoretest\xEF\xBC\xA0" "example.invalid"), mailbox},
        {"test_mailbox", json("restoretest\xE2\x80\x8B@example.invalid"), mailbox},
        {"test_mailbox", json("restoretest@z\xC3\xBC" "rich.invalid"), mailbox},
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
        // The IDs go into Entra and Graph URLs: a GUID, nothing else. A domain
        // name would sign in too, so it is refused plainly.
        {"graph_tenant_id", json("example.onmicrosoft.com"), guid},
        {"graph_tenant_id", json("tenant"), guid},
        {"graph_tenant_id", json("common"), guid},
        {"graph_tenant_id", json("organizations"), guid},
        {"graph_tenant_id", json("{00000000-0000-0000-0000-000000000001}"), guid},
        {"graph_tenant_id", json(" 00000000-0000-0000-0000-000000000001"), guid},
        {"graph_tenant_id", json("00000000-0000-0000-0000-000000000001 "), guid},
        {"graph_tenant_id", json("00000000000000000000000000000000"), guid},
        {"graph_tenant_id", json("00000000-0000-0000-0000-00000000001"), guid},
        {"graph_tenant_id", json("00000000-0000-0000-0000-0000000000011"), guid},
        {"graph_tenant_id", json("00000000-0000-0000-0000-00000000000g"), guid},
        {"graph_tenant_id", json("00000000-0000-0000-0000-000000000001/x"), guid},
        {"graph_client_id", json("client"), guid},
        {"graph_client_id", json("RestoreProof Worker"), guid},
        {"graph_client_id", json("00000000_0000_0000_0000_000000000002"), guid},
        {"graph_client_id", json("0000000-00000-0000-0000-000000000002"), guid},
        // A fullwidth digit zero (U+FF10) looks like a 0.
        {"graph_client_id", json("\xEF\xBC\x90" "0000000-0000-0000-0000-000000000002"), guid},
        {"log_level", json("INFO"), "must be one of trace, debug, info, warn, error, critical, off"},
        {"log_level", json("warning"), "must be one of trace, debug, info, warn, error, critical, off"},
        {"log_level", json("info "), "must be one of trace, debug, info, warn, error, critical, off"},
        {"veeam_ca_file", json(""), "must not be empty"},
        {"veeam_ca_file", json("C:\\ca.pem\n"), control},
        {"veeam_ca_file", json("C:\\\xE2\x80\xAE" "mep.ac"), control},
        // The Worker runs as a service whose working directory is System32, so
        // a path that depends on it (or on the current drive) is rejected.
        {"veeam_ca_file", json("ca.pem"), absolute},
        {"veeam_ca_file", json(".\\ca.pem"), absolute},
        {"veeam_ca_file", json("..\\ca.pem"), absolute},
        {"veeam_ca_file", json("RestoreProof\\veeam-ca.pem"), absolute},
        {"veeam_ca_file", json("\\ca.pem"), absolute},
        {"veeam_ca_file", json("/ca.pem"), absolute},
        {"veeam_ca_file", json("C:ca.pem"), absolute},
        {"veeam_ca_file", json("C:"), absolute},
        {"veeam_ca_file", json(" C:\\ca.pem"), absolute},
        {"veeam_ca_file", json("\xD1\x82\xD0\xB5\xD1\x81\xD1\x82.pem"), absolute},
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

TEST_CASE("parse_config checks veeam_ca_file after log_level", "[config]")
{
    json doc = valid_doc();
    doc["veeam_ca_file"] = "ca.pem";
    doc["log_level"] = "loud";
    REQUIRE(parse_error(doc.dump()).key() == "log_level");
}

TEST_CASE("parse_config checks veeam_ca_file before the sample sizes together", "[config]")
{
    json doc = valid_doc();
    doc["veeam_ca_file"] = "ca.pem";
    doc["sample_mail"] = 0;
    doc["sample_sp"] = 0;
    doc["sample_od"] = 0;
    REQUIRE(parse_error(doc.dump()).key() == "veeam_ca_file");
}

TEST_CASE("parse_config rejects a veeam_cert_sha256 that isn't a SHA-256, without echoing it",
          "[config]")
{
    const std::string sha256 =
        "must be the certificate's SHA-256: 64 hexadecimal digits, as Windows shows it";
    const std::string control = "must not contain control characters";
    const auto [value, rule] = GENERATE_COPY(table<std::string, std::string>({
        {"", "must not be empty"},
        {kCertSha256.substr(0, 63) + "\n", control},
        {"\x1b[2J" + kCertSha256, control},
        {kCertSha256 + "\xE2\x80\xAE", control},
        {kCertSha256.substr(0, 63), sha256},
        {kCertSha256 + "A", sha256},
        {std::string(128, 'A'), sha256},
        // The colon-separated form `openssl x509 -fingerprint` prints, and the
        // spaced form of the Windows certificate dialog.
        {"9F:B1:9E:0E:60:4C:9B:E4:9F:83:D8:E5:08:EF:A8:EA:09:86:A9:52:37:7C:78:3E:50:35:CE:A2:"
         "D7:72:A2:13",
         sha256},
        {"9f b1 9e 0e 60 4c 9b e4 9f 83 d8 e5 08 ef a8 ea 09 86 a9 52 37 7c 78 3e 50 35 ce a2 "
         "d7 72 a2 13",
         sha256},
        {" " + kCertSha256, sha256},
        {kCertSha256 + " ", sha256},
        {"0x" + kCertSha256.substr(2), sha256},
        {kCertSha256.substr(0, 63) + "G", sha256},
        {"SENTINEL-5e0c" + std::string(51, 'A'), sha256},
        // A fullwidth digit zero (U+FF10) looks like hex but isn't.
        {"\xEF\xBC\x90" + kCertSha256.substr(1), sha256},
        // The SHA-1 thumbprint the Veeam console shows: 40 digits.
        {"895C6325" + std::string(32, 'B'), sha256},
    }));
    CAPTURE(value);
    json doc = valid_doc();
    doc["veeam_ca_file"] = kCaFile;
    doc["veeam_cert_sha256"] = value;

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == "veeam_cert_sha256");
    // An exact match also proves the value isn't echoed.
    REQUIRE(std::string{e.what()} == "config key \"veeam_cert_sha256\" " + rule);
}

TEST_CASE("parse_config rejects veeam_cert_sha256 without veeam_ca_file", "[config]")
{
    // The pin names a certificate that veeam_ca_file must hold: without the
    // file there is nothing to trust it through.
    json doc = valid_doc();
    doc["veeam_cert_sha256"] = kCertSha256;

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == "veeam_cert_sha256");
    REQUIRE(std::string{e.what()} == "config key \"veeam_cert_sha256\" needs veeam_ca_file: set "
                                     "it to a PEM file holding that certificate");
}

TEST_CASE("parse_config checks veeam_cert_sha256's form before asking for veeam_ca_file",
          "[config]")
{
    json doc = valid_doc();
    doc["veeam_cert_sha256"] = "not-a-hash";

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == "veeam_cert_sha256");
    REQUIRE_THAT(e.what(), ContainsSubstring("must be the certificate's SHA-256"));
}

TEST_CASE("parse_config checks veeam_cert_sha256 after veeam_ca_file", "[config]")
{
    json doc = valid_doc();
    doc["veeam_ca_file"] = "ca.pem";
    doc["veeam_cert_sha256"] = "not-a-hash";
    REQUIRE(parse_error(doc.dump()).key() == "veeam_ca_file");
}

TEST_CASE("parse_config checks veeam_cert_sha256 before the sample sizes together", "[config]")
{
    json doc = valid_doc();
    doc["veeam_ca_file"] = kCaFile;
    doc["veeam_cert_sha256"] = "not-a-hash";
    doc["sample_mail"] = 0;
    doc["sample_sp"] = 0;
    doc["sample_od"] = 0;
    REQUIRE(parse_error(doc.dump()).key() == "veeam_cert_sha256");
}

TEST_CASE("parse_config rejects a screenshots_enabled that isn't true or false, without echoing "
          "it",
          "[config]")
{
    // The config's one boolean (W4.2): JSON's true or false, nothing that only
    // reads like one.
    const json value = GENERATE(json("true"), json("false"), json("SENTINEL-b7d3"), json(""),
                                json(1), json(0), json(1.0), json(nullptr), json::array(),
                                json::array({true}), json::object());
    CAPTURE(value.dump());
    json doc = valid_doc();
    doc["screenshots_enabled"] = value;

    const rp::ConfigError e = parse_error(doc.dump());
    REQUIRE(e.key() == "screenshots_enabled");
    // An exact match also proves the value isn't echoed.
    REQUIRE(std::string{e.what()} == "config key \"screenshots_enabled\" must be true or false");
}

TEST_CASE("parse_config checks screenshots_enabled after veeam_cert_sha256", "[config]")
{
    json doc = valid_doc();
    doc["veeam_ca_file"] = kCaFile;
    doc["veeam_cert_sha256"] = "not-a-hash";
    doc["screenshots_enabled"] = "true";
    REQUIRE(parse_error(doc.dump()).key() == "veeam_cert_sha256");
}

TEST_CASE("parse_config checks screenshots_enabled before the sample sizes together", "[config]")
{
    json doc = valid_doc();
    doc["screenshots_enabled"] = "true";
    doc["sample_mail"] = 0;
    doc["sample_sp"] = 0;
    doc["sample_od"] = 0;
    REQUIRE(parse_error(doc.dump()).key() == "screenshots_enabled");
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
        // The local part in any case: Exchange addresses are case-insensitive.
        {"test_mailbox", json("RestoreTest@Example.Invalid")},
        {"test_mailbox", json("RESTORETEST@x.y")},
        {"test_mailbox", json("restoretest@my-tenant.example-1.invalid")},
        // Non-ASCII UTF-8 bytes are above 0x7F, not control characters.
        {"veeam_org_name", json("caf\xc3\xa9")},
        {"veeam_org_name", json("Z\xC3\xBC" "rich")},
        {"veeam_org_name", json("\xE6\x9D\xB1\xE4\xBA\xAC")},
        // Just outside the rejected ranges: U+00A0, U+061B, U+061D, U+200D, U+2027,
        // U+202F, U+2065, U+206A.
        {"veeam_org_name", json("a\xC2\xA0" "b")},
        {"veeam_org_name", json("a\xD8\x9B" "b")},
        {"veeam_org_name", json("a\xD8\x9D" "b")},
        {"veeam_org_name", json("a\xE2\x80\x8D" "b")},
        {"veeam_org_name", json("a\xE2\x80\xA7" "b")},
        {"veeam_org_name", json("a\xE2\x80\xAF" "b")},
        {"veeam_org_name", json("a\xE2\x81\xA5" "b")},
        {"veeam_org_name", json("a\xE2\x81\xAA" "b")},
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
        // Absolute: a drive and a root, a UNC share, either slash, any script.
        {"veeam_ca_file", json(kCaFile)},
        {"veeam_ca_file", json("c:/ProgramData/RestoreProof/veeam-ca.pem")},
        {"veeam_ca_file", json("\\\\server\\share\\veeam-ca.pem")},
        {"veeam_ca_file", json("D:\\\xD1\x82\xD0\xB5\xD1\x81\xD1\x82\\ca.pem")},
        {"veeam_ca_file", json("C:\\Program Files\\Veeam CA\\ca.crt")},
    }));
    CAPTURE(key, value.dump());
    json doc = valid_doc();
    doc[key] = value;

    const rp::Config config = rp::parse_config(doc.dump());
    const json parsed{
        {"cloud_url", config.cloud_url},
        {"veeam_url", config.veeam_url},
        {"veeam_org_name", config.veeam_org_name},
        {"test_mailbox", config.test_mailbox},
        {"poll_interval_s", config.poll_interval_s},
        {"heartbeat_interval_s", config.heartbeat_interval_s},
        {"sample_mail", config.sample_mail},
        {"sample_sp", config.sample_sp},
        {"sample_od", config.sample_od},
        {"log_level", config.log_level},
        {"veeam_ca_file", config.veeam_ca_file.value_or("(not set)")},
    };
    REQUIRE(parsed.at(key) == value);
}

TEST_CASE("parse_config accepts graph_tenant_id and graph_client_id as GUIDs in any case",
          "[config]")
{
    const std::string key = GENERATE("graph_tenant_id", "graph_client_id");
    const std::string value =
        GENERATE("bcd6bd1a-ea42-489d-aa28-2c19a44ad146", "BCD6BD1A-EA42-489D-AA28-2C19A44AD146",
                 "Bcd6bd1A-eA42-489d-AA28-2c19a44aD146", "00000000-0000-0000-0000-000000000000",
                 "ffffffff-ffff-ffff-ffff-ffffffffffff");
    CAPTURE(key, value);
    json doc = valid_doc();
    doc[key] = value;

    const rp::Config config = rp::parse_config(doc.dump());
    REQUIRE((key == "graph_tenant_id" ? config.graph_tenant_id : config.graph_client_id) == value);
}

TEST_CASE("parse_config accepts veeam_cert_sha256 in any case, with veeam_ca_file",
          "[config]")
{
    const std::string value = GENERATE_COPY(
        kCertSha256, lower(kCertSha256), std::string(64, '0'),
        std::string{"0123456789abcdefABCDEF"} + std::string(42, 'f'));
    CAPTURE(value);
    json doc = valid_doc();
    doc["veeam_ca_file"] = kCaFile;
    doc["veeam_cert_sha256"] = value;

    const rp::Config config = rp::parse_config(doc.dump());
    REQUIRE(config.veeam_cert_sha256 == value);
    REQUIRE(config.veeam_ca_file == kCaFile);
}

TEST_CASE("parse_config reads screenshots_enabled as written", "[config]")
{
    const bool value = GENERATE(true, false);
    CAPTURE(value);
    json doc = valid_doc();
    doc["screenshots_enabled"] = value;

    REQUIRE(rp::parse_config(doc.dump()).screenshots_enabled == value);
}

TEST_CASE("parse_config reads every key", "[config]")
{
    json doc = valid_doc();
    doc["veeam_ca_file"] = kCaFile;
    doc["veeam_cert_sha256"] = kCertSha256;
    doc["screenshots_enabled"] = true;
    const rp::Config config = rp::parse_config(doc.dump(2));

    REQUIRE(config.cloud_url == "https://cloud.example.invalid");
    REQUIRE(config.veeam_url == "https://veeam.example.invalid:4443");
    REQUIRE(config.veeam_org_name == "example.onmicrosoft.com");
    REQUIRE(config.graph_tenant_id == "00000000-0000-0000-0000-000000000001");
    REQUIRE(config.graph_client_id == "00000000-0000-0000-0000-000000000002");
    REQUIRE(config.test_mailbox == "restoretest@example.onmicrosoft.com");
    REQUIRE(config.test_site_id == "example.sharepoint.com,00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002");
    REQUIRE(config.test_library_id == "b!library-id");
    REQUIRE(config.test_onedrive_drive_id == "b!drive-id");
    REQUIRE(config.test_onedrive_folder_id == "folder-id");
    REQUIRE(config.poll_interval_s == 60);
    REQUIRE(config.heartbeat_interval_s == 120);
    REQUIRE(config.sample_mail == 1);
    REQUIRE(config.sample_sp == 2);
    REQUIRE(config.sample_od == 3);
    REQUIRE(config.log_level == "debug");
    REQUIRE(config.veeam_ca_file == kCaFile);
    REQUIRE(config.veeam_cert_sha256 == kCertSha256);
    REQUIRE(config.screenshots_enabled);
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
    // No CA file: the Windows certificate store is trusted.
    REQUIRE_FALSE(config.veeam_ca_file.has_value());
    // No pin: with a CA file, the host name would be checked as usual.
    REQUIRE_FALSE(config.veeam_cert_sha256.has_value());
    // No screenshot unless the client's setting asks for one.
    REQUIRE_FALSE(config.screenshots_enabled);
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

TEST_CASE("load_config rejects a veeam_ca_file it can't read, without the file's path",
          "[config]")
{
    const rp::test::TempDir dir;
    std::filesystem::create_directory(dir.path() / "ca-dir.pem");
    // Cyrillic letters: not in cp1252, the ANSI code page of a Western machine.
    const std::filesystem::path ca = GENERATE_REF(
        dir.path() / "missing.pem", dir.path() / "ca-dir.pem",
        dir.path() / std::filesystem::path(u8"тест-missing.pem"));
    CAPTURE(utf8(ca));
    json doc = valid_doc();
    doc["veeam_ca_file"] = utf8(ca);
    const auto path = dir.write("config.json", doc.dump());

    const rp::ConfigError e = load_error(path);
    REQUIRE(e.key() == "veeam_ca_file");
    REQUIRE(std::string{e.what()} ==
            utf8(path) + ": config key \"veeam_ca_file\" names a file that can't be read");
}

TEST_CASE("load_config accepts a veeam_ca_file it can read", "[config]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path name =
        GENERATE(std::filesystem::path("veeam-ca.pem"),
                 std::filesystem::path(u8"тест-ca.pem"));
    const std::filesystem::path ca =
        dir.write(name, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n");
    CAPTURE(utf8(ca));
    json doc = valid_doc();
    doc["veeam_ca_file"] = utf8(ca);
    const auto path = dir.write("config.json", doc.dump());

    const rp::Config config = rp::load_config(path);
    REQUIRE(config.veeam_ca_file == utf8(ca));
}

TEST_CASE("load_config accepts a veeam_cert_sha256 that veeam_ca_file holds", "[config]")
{
    const rp::test::TempDir dir;
    const rp::test::Cert cert =
        rp::test::make_cert("Veeam Software", rp::test::Role::veeam_default);
    const std::filesystem::path ca = dir.write("veeam-rest.pem", cert.pem().cert);
    // A loop, not GENERATE: each run of the test makes a new certificate.
    for (const std::string& sha256 :
         {rp::test::cert_sha256_hex(cert), lower(rp::test::cert_sha256_hex(cert))}) {
        CAPTURE(sha256);
        json doc = valid_doc();
        doc["veeam_ca_file"] = utf8(ca);
        doc["veeam_cert_sha256"] = sha256;
        const auto path = dir.write("config.json", doc.dump());

        const rp::Config config = rp::load_config(path);
        REQUIRE(config.veeam_ca_file == utf8(ca));
        REQUIRE(config.veeam_cert_sha256 == sha256);
    }
}

TEST_CASE("load_config rejects a veeam_cert_sha256 that veeam_ca_file doesn't hold",
          "[config]")
{
    const rp::test::TempDir dir;
    const rp::test::Cert held =
        rp::test::make_cert("Veeam Software", rp::test::Role::veeam_default);
    const rp::test::Cert other =
        rp::test::make_cert("Veeam Software", rp::test::Role::veeam_default);
    const std::filesystem::path ca = dir.write("veeam-rest.pem", held.pem().cert);
    json doc = valid_doc();
    doc["veeam_ca_file"] = utf8(ca);
    doc["veeam_cert_sha256"] = rp::test::cert_sha256_hex(other);
    const auto path = dir.write("config.json", doc.dump());

    const rp::ConfigError e = load_error(path);
    REQUIRE(e.key() == "veeam_cert_sha256");
    REQUIRE(std::string{e.what()} ==
            utf8(path) + ": config key \"veeam_cert_sha256\": veeam_ca_file holds no certificate "
                         "whose SHA-256 is veeam_cert_sha256");
}

TEST_CASE("load_config reports an unreadable veeam_ca_file before checking the pin", "[config]")
{
    const rp::test::TempDir dir;
    json doc = valid_doc();
    doc["veeam_ca_file"] = utf8(dir.path() / "missing.pem");
    doc["veeam_cert_sha256"] = kCertSha256;
    const auto path = dir.write("config.json", doc.dump());

    const rp::ConfigError e = load_error(path);
    REQUIRE(e.key() == "veeam_ca_file");
    REQUIRE(std::string{e.what()} ==
            utf8(path) + ": config key \"veeam_ca_file\" names a file that can't be read");
}

TEST_CASE("load_config reports a veeam_ca_file's form before trying to read it", "[config]")
{
    const rp::test::TempDir dir;
    json doc = valid_doc();
    doc["veeam_ca_file"] = "missing.pem";
    const auto path = dir.write("config.json", doc.dump());

    REQUIRE_THAT(load_error(path).what(), ContainsSubstring("must be an absolute path"));
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
    REQUIRE_FALSE(config.screenshots_enabled);
}

TEST_CASE("config.example.json sets every key but veeam_ca_file and veeam_cert_sha256",
          "[config]")
{
    // veeam_ca_file must name a file that exists, so a placeholder would make
    // the example fail to load, and veeam_cert_sha256 needs veeam_ca_file (and
    // a certificate in it); docs/worker-config.md documents both instead.
    std::ifstream file(std::filesystem::path(RP_CONFIG_EXAMPLE));
    const json doc = json::parse(file);
    REQUIRE(doc.size() == 17);
    REQUIRE(doc.at("screenshots_enabled") == false);
    REQUIRE_FALSE(doc.contains("veeam_ca_file"));
    REQUIRE_FALSE(doc.contains("veeam_cert_sha256"));
}

TEST_CASE("parse_config takes Graph IDs of every allowed shape", "[config]")
{
    const std::string g = "0A1B2C3D-0000-4000-8000-00000000ABCD";
    json doc = valid_doc();
    doc["test_site_id"] = GENERATE_COPY(as<std::string>{}, "T-1.SharePoint.COM," + g + "," + g,
                                        std::string(63, 't') + ".sharepoint.com," + g + "," + g);
    doc["test_library_id"] = "b!" + std::string(200, 'a');
    doc["test_onedrive_drive_id"] = "b!Az09-_";
    doc["test_onedrive_folder_id"] = "a!b-c_" + std::string(194, 'd');

    const rp::Config config = rp::parse_config(doc.dump());

    CHECK(config.test_site_id == doc["test_site_id"].get<std::string>());
}

TEST_CASE("onedrive_host: a tenant's SharePoint host gives its -my host, in lower case",
          "[config]")
{
    CHECK(rp::onedrive_host("restoreprooflab.sharepoint.com") ==
          "restoreprooflab-my.sharepoint.com");
    CHECK(rp::onedrive_host("T-1.SharePoint.COM") == "t-1-my.sharepoint.com");
    // Only "<tenant>.sharepoint.com", the tenant one DNS label.
    const std::string bad = GENERATE(as<std::string>{}, "", ".sharepoint.com", "sharepoint.com",
                                     "a.b.sharepoint.com", "evil.example",
                                     "restoreprooflab.sharepoint.com.evil.example",
                                     "restore_prooflab.sharepoint.com", "restoreprooflab.sharepoint.co");
    CAPTURE(bad);
    CHECK_FALSE(rp::onedrive_host(bad));
}

TEST_CASE("parse_graph_site_id splits a site ID, the host in lower case", "[config]")
{
    const std::optional<rp::GraphSiteId> site = rp::parse_graph_site_id(
        "T-1.SharePoint.COM,0a1b2c3d-0000-4000-8000-00000000abcd,0a1b2c3d-0000-4000-8000-00000000abce");
    REQUIRE(site);
    CHECK(site->host == "t-1.sharepoint.com");
    CHECK(site->site == "0a1b2c3d-0000-4000-8000-00000000abcd");
    CHECK(site->web == "0a1b2c3d-0000-4000-8000-00000000abce");
    CHECK_FALSE(rp::parse_graph_site_id("host"));
}

// --- W4.4: the TSA's URL and its CA file ------------------------------------------

TEST_CASE("without tsa_url and tsa_ca_file the config has neither", "[config][tsa]")
{
    const rp::Config config = rp::parse_config(valid_doc().dump());
    CHECK_FALSE(config.tsa_url);
    CHECK_FALSE(config.tsa_ca_file);
}

TEST_CASE("parse_config takes an http or an https tsa_url with its tsa_ca_file", "[config][tsa]")
{
    const std::string url = GENERATE("http://timestamp.sectigo.com", "https://freetsa.org/tsr",
                                     "HTTP://tsa.example:8080/stamp", "http://127.0.0.1:9/");
    json doc = valid_doc();
    doc["tsa_url"] = url;
    doc["tsa_ca_file"] = "C:\\ProgramData\\RestoreProof\\tsa-ca.pem";
    const rp::Config config = rp::parse_config(doc.dump());
    CHECK(config.tsa_url == url);
    CHECK(config.tsa_ca_file == "C:\\ProgramData\\RestoreProof\\tsa-ca.pem");
}

TEST_CASE("parse_config rejects a tsa_url that isn't an http or https URL, without echoing it",
          "[config][tsa]")
{
    const std::string url = GENERATE(
        "ftp://tsa.example/stamp", "tsa.example", "http://", "http:///stamp", "file:///c:/tsa",
        "http://user@tsa.example/", "http://user:SENTINEL@tsa.example/",
        "http://tsa.example/stamp?key=SENTINEL", "http://tsa.example/stamp#SENTINEL",
        "http://tsa.example/st amp", "http://ts\xD0\xB0.example/", " http://tsa.example/");
    CAPTURE(url);
    json doc = valid_doc();
    doc["tsa_url"] = url;
    doc["tsa_ca_file"] = "C:\\tsa-ca.pem";

    const rp::ConfigError e = parse_error(doc.dump());

    CHECK(e.key() == "tsa_url");
    CHECK(std::string{e.what()} ==
          "config key \"tsa_url\" must be an http:// or https:// URL with no user name, "
          "password, query or fragment");
}

TEST_CASE("a tsa_url needs its tsa_ca_file: another TSA never borrows the default's root",
          "[config][tsa]")
{
    json doc = valid_doc();
    doc["tsa_url"] = "http://timestamp.sectigo.com";

    const rp::ConfigError e = parse_error(doc.dump());

    CHECK(e.key() == "tsa_url");
    CHECK(std::string{e.what()} ==
          "config key \"tsa_url\" needs tsa_ca_file: set it to a PEM file holding the "
          "certificate(s) that TSA's tokens chain to");
}

TEST_CASE("a tsa_ca_file alone replaces the root for the default TSA", "[config][tsa]")
{
    json doc = valid_doc();
    doc["tsa_ca_file"] = "C:\\tsa-ca.pem";
    const rp::Config config = rp::parse_config(doc.dump());
    CHECK_FALSE(config.tsa_url);
    CHECK(config.tsa_ca_file == "C:\\tsa-ca.pem");
}

TEST_CASE("parse_config rejects a tsa_ca_file that isn't an absolute path", "[config][tsa]")
{
    const std::string value = GENERATE("tsa-ca.pem", ".\\tsa-ca.pem", "\\tsa-ca.pem", "C:tsa.pem");
    json doc = valid_doc();
    doc["tsa_ca_file"] = value;

    const rp::ConfigError e = parse_error(doc.dump());

    CHECK(e.key() == "tsa_ca_file");
    CHECK(std::string{e.what()} ==
          "config key \"tsa_ca_file\" must be an absolute path, such as "
          "C:\\ProgramData\\RestoreProof\\tsa-ca.pem");
}

TEST_CASE("the TSA keys are strings, and empty is refused", "[config][tsa]")
{
    const std::string key = GENERATE("tsa_url", "tsa_ca_file");
    json doc = valid_doc();
    doc["tsa_ca_file"] = "C:\\tsa-ca.pem";
    SECTION("another JSON type")
    {
        doc[key] = 1;
        CHECK(parse_error(doc.dump()).key() == key);
    }
    SECTION("empty")
    {
        doc[key] = "";
        CHECK(parse_error(doc.dump()).key() == key);
    }
}

TEST_CASE("the TSA keys are checked after veeam_cert_sha256 and before screenshots_enabled",
          "[config][tsa]")
{
    json doc = valid_doc();
    doc["tsa_url"] = "ftp://tsa.example";
    doc["screenshots_enabled"] = "yes";
    CHECK(parse_error(doc.dump()).key() == "tsa_url");
    doc["veeam_cert_sha256"] = "not a hash";
    doc["veeam_ca_file"] = kCaFile;
    CHECK(parse_error(doc.dump()).key() == "veeam_cert_sha256");
}

TEST_CASE("load_config rejects a tsa_ca_file that can't be opened", "[config][tsa]")
{
    const rp::test::TempDir dir;
    std::filesystem::create_directory(dir.path() / "ca-dir.pem");
    const std::filesystem::path ca =
        GENERATE_REF(dir.path() / "missing.pem", dir.path() / "ca-dir.pem");
    json doc = valid_doc();
    doc["tsa_ca_file"] = utf8(ca);
    const auto path = dir.write("config.json", doc.dump());

    const rp::ConfigError e = load_error(path);

    CHECK(e.key() == "tsa_ca_file");
    CHECK(std::string{e.what()} ==
          utf8(path) + ": config key \"tsa_ca_file\" names a file that can't be read");
}

TEST_CASE("load_config takes a tsa_ca_file that is there", "[config][tsa]")
{
    const rp::test::TempDir dir;
    const auto ca = dir.write("tsa-ca.pem", "-----BEGIN CERTIFICATE-----\n");
    json doc = valid_doc();
    doc["tsa_url"] = "http://tsa.example/stamp";
    doc["tsa_ca_file"] = utf8(ca);
    const auto path = dir.write("config.json", doc.dump());

    const rp::Config config = rp::load_config(path);

    CHECK(config.tsa_url == "http://tsa.example/stamp");
    CHECK(config.tsa_ca_file == utf8(ca));
}

// --- W4.6: the Cloud's CA file -------------------------------------------------------

TEST_CASE("without cloud_ca_file the config has none", "[config][outbox]")
{
    CHECK_FALSE(rp::parse_config(valid_doc().dump()).cloud_ca_file);
}

TEST_CASE("parse_config takes an absolute cloud_ca_file, and cloud_url stays https",
          "[config][outbox]")
{
    json doc = valid_doc();
    doc["cloud_ca_file"] = "C:\\ProgramData\\RestoreProof\\cloud-ca.pem";
    CHECK(rp::parse_config(doc.dump()).cloud_ca_file ==
          "C:\\ProgramData\\RestoreProof\\cloud-ca.pem");
    // A CA file is what to trust, never a way to an http Cloud.
    doc["cloud_url"] = "http://localhost:8443";
    CHECK(parse_error(doc.dump()).key() == "cloud_url");
}

TEST_CASE("parse_config rejects a cloud_ca_file that isn't an absolute path", "[config][outbox]")
{
    const std::string value = GENERATE("cloud-ca.pem", ".\\cloud-ca.pem", "\\cloud-ca.pem", "C:ca.pem");
    json doc = valid_doc();
    doc["cloud_ca_file"] = value;

    const rp::ConfigError e = parse_error(doc.dump());

    CHECK(e.key() == "cloud_ca_file");
    CHECK(std::string{e.what()} ==
          "config key \"cloud_ca_file\" must be an absolute path, such as "
          "C:\\ProgramData\\RestoreProof\\cloud-ca.pem");
}

TEST_CASE("cloud_ca_file is a string, empty is refused, and it is checked after the TSA's keys "
          "and before screenshots_enabled",
          "[config][outbox]")
{
    json doc = valid_doc();
    doc["cloud_ca_file"] = 1;
    CHECK(parse_error(doc.dump()).key() == "cloud_ca_file");
    doc["cloud_ca_file"] = "";
    CHECK(parse_error(doc.dump()).key() == "cloud_ca_file");
    doc["screenshots_enabled"] = "yes";
    CHECK(parse_error(doc.dump()).key() == "cloud_ca_file");
    doc["tsa_url"] = "ftp://tsa.example";
    CHECK(parse_error(doc.dump()).key() == "tsa_url");
}

TEST_CASE("load_config rejects a cloud_ca_file that can't be opened", "[config][outbox]")
{
    const rp::test::TempDir dir;
    std::filesystem::create_directory(dir.path() / "ca-dir.pem");
    const std::filesystem::path ca =
        GENERATE_REF(dir.path() / "missing.pem", dir.path() / "ca-dir.pem");
    json doc = valid_doc();
    doc["cloud_ca_file"] = utf8(ca);
    const auto path = dir.write("config.json", doc.dump());

    const rp::ConfigError e = load_error(path);

    CHECK(e.key() == "cloud_ca_file");
    CHECK(std::string{e.what()} ==
          utf8(path) + ": config key \"cloud_ca_file\" names a file that can't be read");
}

TEST_CASE("load_config rejects a cloud_ca_file that holds no certificate", "[config][outbox]")
{
    struct Row {
        const char* name;
        std::string bytes;
    };
    const Row row = GENERATE(
        Row{"empty", ""}, Row{"text", "not a certificate"},
        Row{"a cut-off block", "-----BEGIN CERTIFICATE-----\n"},
        Row{"DER, not PEM", std::string("\x30\x82\x01\x00\x30\x82", 6)},
        Row{"a key block alone", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"});
    CAPTURE(row.name);
    const rp::test::TempDir dir;
    const auto ca = dir.write("cloud-ca.pem", row.bytes);
    json doc = valid_doc();
    doc["cloud_ca_file"] = utf8(ca);
    const auto path = dir.write("config.json", doc.dump());

    const rp::ConfigError e = load_error(path);

    CHECK(e.key() == "cloud_ca_file");
    CHECK(std::string{e.what()} ==
          utf8(path) +
              ": config key \"cloud_ca_file\" names a file that holds no certificate (PEM)");
}

TEST_CASE("load_config takes a cloud_ca_file that is there and holds a certificate",
          "[config][outbox]")
{
    const rp::test::TempDir dir;
    const auto ca = dir.write("cloud-ca.pem", std::string{rp::default_tsa_ca_pem()});
    json doc = valid_doc();
    doc["cloud_ca_file"] = utf8(ca);
    const auto path = dir.write("config.json", doc.dump());

    CHECK(rp::load_config(path).cloud_ca_file == utf8(ca));
}

// --- W4.8: the jobs file and the service's folders ------------------------------------

TEST_CASE("without jobs_file the config has none", "[config][jobs]")
{
    CHECK_FALSE(rp::parse_config(valid_doc().dump()).jobs_file);
}

TEST_CASE("parse_config rejects a jobs_file that isn't an absolute path", "[config][jobs]")
{
    const std::string value =
        GENERATE("jobs.json", ".\\jobs.json", "..\\jobs.json", "\\jobs.json", "C:jobs.json",
                 "state/jobs.json");
    CAPTURE(value);
    json doc = valid_doc();
    doc["jobs_file"] = value;

    const rp::ConfigError e = parse_error(doc.dump());

    CHECK(e.key() == "jobs_file");
    CHECK(std::string{e.what()} == "config key \"jobs_file\" must be an absolute path, such as "
                                   "C:\\ProgramData\\RestoreProof\\jobs.json");
}

TEST_CASE("jobs_file is a string, empty is refused, and it is checked after cloud_ca_file and "
          "before screenshots_enabled",
          "[config][jobs]")
{
    json doc = valid_doc();
    doc["jobs_file"] = 1;
    CHECK(parse_error(doc.dump()).key() == "jobs_file");
    doc["jobs_file"] = nullptr;
    CHECK(parse_error(doc.dump()).key() == "jobs_file");
    doc["jobs_file"] = "";
    CHECK(parse_error(doc.dump()).key() == "jobs_file");
    doc["screenshots_enabled"] = "yes";
    CHECK(parse_error(doc.dump()).key() == "jobs_file");
    doc["cloud_ca_file"] = "cloud-ca.pem";
    CHECK(parse_error(doc.dump()).key() == "cloud_ca_file");
}

TEST_CASE("parse_config takes an absolute jobs_file, on a drive or a share", "[config][jobs]")
{
    const std::string value = GENERATE("C:\\ProgramData\\RestoreProof\\jobs.json",
                                       "\\\\server\\share\\jobs.json", "D:/lab/jobs.json");
    json doc = valid_doc();
    doc["jobs_file"] = value;

    CHECK(rp::parse_config(doc.dump()).jobs_file == value);
}

TEST_CASE("load_config never opens the jobs file: one that isn't there, a folder and text that "
          "is no jobs document all load",
          "[config][jobs]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path jobs = dir.path() / "jobs.json";
    json doc = valid_doc();
    doc["jobs_file"] = utf8(jobs);
    const std::filesystem::path path = dir.write("config.json", doc.dump());

    SECTION("not there") {}
    SECTION("a folder") { std::filesystem::create_directory(jobs); }
    SECTION("not a jobs document") { dir.write("jobs.json", "SENTINEL-jobs"); }

    CHECK(rp::load_config(path).jobs_file == utf8(jobs));
}

TEST_CASE("the service's runs root and state folder are in RestoreProof under ProgramData",
          "[config][jobs]")
{
    const std::filesystem::path home = rp::default_config_path().parent_path();

    CHECK(rp::default_runs_root() == rp::program_data_dir() / "RestoreProof" / "runs");
    CHECK(rp::default_state_dir() == rp::program_data_dir() / "RestoreProof" / "state");
    CHECK(rp::default_runs_root().parent_path() == home);
    CHECK(rp::default_state_dir().parent_path() == home);
}
