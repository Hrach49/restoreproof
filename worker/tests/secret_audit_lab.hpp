#pragma once

// The secret audit's lab (W4.9, docs/decisions.md 2026-10-09): the five
// sentinel secrets a run is given, the values derived from them that the
// fakes hand out, the set of bytes an output may never hold, the collector of
// everything a run wrote, and the search. Nothing here prints a secret: a hit
// names the output, the secret's label and the byte offset.
//
// The shapes searched for beside the values are the fixture scan's
// (tools/fixture_secret_scan.py), minus the keyed rule, which the values
// cover here: a JWT, a Bearer token, a PEM private key block, the Base64
// opening of a private key's DER (Ed25519, RSA and EC in PKCS#8, RSA PKCS#1,
// EC SEC1) and of a PKCS#12 file. docs/testing.md holds the one table.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "signing_lab.hpp"
#include "test_certs.hpp"

#include <rp/base64.hpp>
#include <rp/http_client.hpp>
#include <rp/redact.hpp>
#include <rp/secrets.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp::test::secret_audit {

// The vault values (docs/decisions.md 2026-10-09 W4.9 point 2; W5.1's two below). The user
// name is no secret value and is only counted.
inline constexpr std::string_view kUserName = "AUDIT-HOST\\rp-veeam-audit-2d7f";
inline constexpr std::string_view kBareUserName = "rp-veeam-audit-2d7f";
inline constexpr std::string_view kVeeamPassword = "Sentinel-Audit-Veeam-Password-2d7f";
inline constexpr std::string_view kPfxPassword = "Sentinel-Audit-PFX-Password-2d7f";
// What the fakes hand out at run time.
inline constexpr std::string_view kVeeamAccessToken =
    "Sentinel-Audit-Veeam-Access-Token-2d7f-0123456789abcdef";
inline constexpr std::string_view kVeeamRefreshToken =
    "Sentinel-Audit-Veeam-Refresh-Token-2d7f-0123456789abcdef";
inline constexpr std::string_view kGraphAccessToken = "Sentinel-Audit-Graph-Access-Token-2d7f";
inline constexpr std::string_view kExportedPfxPassword =
    "Sentinel-Audit-Exported-PFX-Password-2d7f";
// The Cloud's two vault tokens (W5.1, docs/decisions.md 2026-10-15 point 10),
// 43 base64url characters as the Cloud makes them, and the API token a fake
// Cloud's registration answers with.
inline constexpr std::string_view kInstallToken = "SentinelAuditInstallToken-2d7f-0123456789ab";
inline constexpr std::string_view kApiToken = "SentinelAuditApiToken-2d7f-0123456789abcdef";
inline constexpr std::string_view kIssuedApiToken = "SentinelAuditIssuedToken-2d7f-0123456789abc";

// The exported restore credential: a restore body carries a Base64 PFX, so
// the sentinel is the Base64 of its own words.
inline const std::string& exported_pfx()
{
    static const std::string value = [] {
        const std::string_view words = "Sentinel-Audit-Exported-PFX-2d7f";
        return rp::base64_encode(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(words.data()), words.size()));
    }();
    return value;
}

// The Worker app's certificate as the audit's vault holds it: a PFX of its
// own (a fresh key, never the Harness's shared one), valid at graph_lab::kNow,
// under kPfxPassword. Made once per process.
inline const std::string& pfx_base64()
{
    static const std::string pfx = rp::test::to_base64(rp::test::make_pfx(
        rp::test::make_client_cert("RestoreProof Worker (secret audit)",
                                   rp::test::ClientCertOptions{
                                       .fresh_key = true,
                                       .now = std::chrono::system_clock::to_time_t(
                                           rp::test::graph_lab::kNow)}),
        std::string{kPfxPassword}.c_str()));
    return pfx;
}

// The signing key: RFC 8032's test key 2, never key 1, the Harness's default.
inline std::string signing_key_base64()
{
    return rp::test::signing_key2_base64();
}

inline rp::Secrets secrets()
{
    return rp::Secrets{std::string{kUserName},    std::string{kVeeamPassword}, pfx_base64(),
                       std::string{kPfxPassword}, signing_key_base64(),        std::string{kInstallToken},
                       std::string{kApiToken}};
}

// The recorded token replies with the audit's tokens in place of the
// placeholders.
inline rp::HttpResponse graph_token_response()
{
    nlohmann::json fixture = load_fixture_json("graph", "token-200");
    fixture["body"]["access_token"] = std::string{kGraphAccessToken};
    return to_response(fixture);
}

inline rp::HttpResponse veeam_token_response()
{
    nlohmann::json fixture = load_fixture_json("veeam", "token-200");
    fixture["body"]["access_token"] = std::string{kVeeamAccessToken};
    fixture["body"]["refresh_token"] = std::string{kVeeamRefreshToken};
    return to_response(fixture);
}

inline std::string hex_of(std::span<const unsigned char> bytes)
{
    constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const unsigned char b : bytes) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 15]);
    }
    return out;
}

// One value no output may hold. The bytes are never printed.
struct Secret {
    std::string label;
    std::string bytes;
};

// The pieces a long value is searched in beside the whole: any leak of 63 or
// more consecutive characters is found.
inline constexpr std::size_t kPiece = 32;

class SecretSet {
public:
    void add(std::string label, std::string bytes)
    {
        REQUIRE(bytes.size() >= 6);
        secrets_.push_back({std::move(label), std::move(bytes)});
    }

    // The whole text and its kPiece-sized pieces.
    void add_with_pieces(const std::string& label, const std::string& text)
    {
        add(label, text);
        if (text.size() <= kPiece) {
            return;
        }
        for (std::size_t at = 0; at + kPiece <= text.size(); at += kPiece) {
            add(label + " piece @" + std::to_string(at), text.substr(at, kPiece));
        }
    }

    // A Base64 value: its text, its bytes and their hex, each with pieces.
    void add_base64(const std::string& label, const std::string& text)
    {
        add_with_pieces(label + " (base64)", text);
        const std::optional<std::vector<unsigned char>> bytes = rp::base64_decode(text);
        REQUIRE(bytes);
        add_with_pieces(label + " (bytes)", std::string(bytes->begin(), bytes->end()));
        add_with_pieces(label + " (hex)", hex_of(*bytes));
    }

    const std::vector<Secret>& all() const noexcept { return secrets_; }

private:
    std::vector<Secret> secrets_;
};

// The audit's values: the four secret vault values in every shape a leak
// could carry, the signing seed as SigningKey::secret_shapes() gives it, and
// the run-time values the fakes hand out. The client assertion is added per
// run from what the fake token endpoint received (client_assertions_in).
inline SecretSet searched()
{
    SecretSet set;
    set.add("veeam_password", std::string{kVeeamPassword});
    set.add_base64("graph_cert_pfx", pfx_base64());
    set.add("graph_cert_password", std::string{kPfxPassword});
    set.add_base64("signing_key", signing_key_base64());
    const std::vector<unsigned char> seed = rp::test::bytes_from_hex(rp::test::kSigningSeed2Hex);
    set.add("signing seed (base64)", rp::base64_encode(seed));
    set.add("signing seed (hex)", std::string{rp::test::kSigningSeed2Hex});
    set.add("veeam access token", std::string{kVeeamAccessToken});
    set.add("veeam refresh token", std::string{kVeeamRefreshToken});
    set.add("graph access token", std::string{kGraphAccessToken});
    set.add("exported pfx", exported_pfx());
    set.add("exported pfx password", std::string{kExportedPfxPassword});
    set.add("cloud install token", std::string{kInstallToken});
    set.add("cloud api token", std::string{kApiToken});
    set.add("issued cloud api token", std::string{kIssuedApiToken});
    return set;
}

// Every client_assertion value in the token requests `graph` received.
inline std::vector<std::string> client_assertions_in(const FakeHttpClient& graph)
{
    std::vector<std::string> out;
    for (const rp::HttpRequest& request : graph.requests()) {
        const std::string_view body = request.body;
        std::size_t at = body.find("client_assertion=");
        while (at != std::string_view::npos) {
            at += 17;
            const std::size_t end = body.find('&', at);
            out.emplace_back(body.substr(at, end == std::string_view::npos ? end : end - at));
            at = body.find("client_assertion=", at);
        }
    }
    return out;
}

inline void add_client_assertions(SecretSet& set, const FakeHttpClient& graph)
{
    std::size_t n = 0;
    for (const std::string& assertion : client_assertions_in(graph)) {
        set.add("client assertion " + std::to_string(++n), assertion);
    }
}

// --- the outputs ----------------------------------------------------------------------

struct Output {
    std::string name;
    std::string bytes;
};

struct Outputs {
    std::vector<Output> items;

    void add(std::string name, std::string bytes) { items.push_back({std::move(name), std::move(bytes)}); }

    // Every regular file under `root`, recursively, as "<label>/<relative path>".
    void add_folder(const std::filesystem::path& root, std::string_view label)
    {
        if (!std::filesystem::exists(root)) {
            return;
        }
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            // A file that can't be read whole is no output searched: the
            // audit must fail, never pass over it.
            std::ifstream file(entry.path(), std::ios::binary);
            REQUIRE(file);
            std::string bytes{std::istreambuf_iterator<char>(file), {}};
            REQUIRE_FALSE(file.bad());
            REQUIRE(bytes.size() == std::filesystem::file_size(entry.path()));
            const std::u8string rel = entry.path().lexically_relative(root).generic_u8string();
            add(std::string{label} + "/" + std::string(rel.begin(), rel.end()), std::move(bytes));
        }
    }

    // Every request `client` received: the URL, each header, the body and
    // each multipart part's name, file name, content type and bytes.
    void add_requests(std::string_view label, const FakeHttpClient& client)
    {
        std::size_t n = 0;
        for (const rp::HttpRequest& request : client.requests()) {
            const std::string prefix = std::string{label} + " request " + std::to_string(++n);
            add(prefix + " url", request.url);
            for (const auto& [name, value] : request.headers) {
                add(prefix + " header " + name, value);
            }
            add(prefix + " body", request.body);
            std::size_t p = 0;
            for (const rp::MultipartPart& part : request.parts) {
                const std::string where = prefix + " part " + std::to_string(++p) + " ";
                add(where + "name", part.name);
                add(where + "filename", part.filename);
                add(where + "content type", part.content_type);
                add(where + "content", part.content);
            }
        }
    }

    // How often `bytes` appears over every output.
    std::size_t count(std::string_view bytes) const
    {
        std::size_t n = 0;
        for (const Output& output : items) {
            std::size_t at = output.bytes.find(bytes);
            while (at != std::string::npos) {
                ++n;
                at = output.bytes.find(bytes, at + 1);
            }
        }
        return n;
    }

    // Whether an output's name holds `part`.
    bool has_output(std::string_view part) const
    {
        for (const Output& output : items) {
            if (output.name.find(part) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
};

// --- the shapes -----------------------------------------------------------------------

inline bool is_base64_char(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' ||
           c == '/';
}

inline bool is_alnum(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

// A word character, as the scan's \b takes it.
inline bool is_word_char(char c) noexcept
{
    return is_alnum(c) || c == '_';
}

// A PEM label of upper-case words and digits, single spaces between, ending
// in PRIVATE KEY: "PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY";
// not "XPRIVATE KEY" (the scan's `(?:[A-Z0-9]+ )*PRIVATE KEY`).
inline bool is_private_key_label(std::string_view label) noexcept
{
    constexpr std::string_view kEnd = "PRIVATE KEY";
    if (!label.ends_with(kEnd)) {
        return false;
    }
    const std::string_view head = label.substr(0, label.size() - kEnd.size());
    if (head.empty()) {
        return true;
    }
    if (!head.ends_with(' ')) {
        return false;
    }
    bool in_word = false;
    for (const char c : head) {
        if (c == ' ') {
            if (!in_word) {
                return false;
            }
            in_word = false;
        } else if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            in_word = true;
        } else {
            return false;
        }
    }
    return true;
}

inline bool one_of(char c, std::string_view set) noexcept
{
    return set.find(c) != std::string_view::npos;
}

struct ShapeHit {
    std::string shape;
    std::size_t offset;
};

// Every shape in `text`, as the fixture scan finds them (its table in
// docs/testing.md).
inline std::vector<ShapeHit> shapes_in(std::string_view text)
{
    std::vector<ShapeHit> hits;
    // A JWT: eyJ not run into a base64url character, then 37 or more
    // base64url characters and dots (rp::kJwtStart, the recorder's rule).
    for (std::size_t at = text.find(rp::kJwtStart); at != std::string_view::npos;
         at = text.find(rp::kJwtStart, at + 1)) {
        if (at > 0 && rp::is_base64url(text[at - 1])) {
            continue;
        }
        std::size_t end = at + 3;
        while (end < text.size() && (rp::is_base64url(text[end]) || text[end] == '.')) {
            ++end;
        }
        if (end - (at + 3) >= 37) {
            hits.push_back({"jwt", at});
        }
    }
    // Bearer <token>: 20 or more token characters and optional padding, not
    // followed by a letter, a digit or '=' (an auth-param's name is).
    for (std::size_t at = text.find("Bearer"); at != std::string_view::npos;
         at = text.find("Bearer", at + 1)) {
        if (at > 0 && is_word_char(text[at - 1])) {
            continue;
        }
        std::size_t p = at + 6;
        const std::size_t blanks = p;
        while (p < text.size() && (text[p] == ' ' || text[p] == '\t')) {
            ++p;
        }
        if (p == blanks) {
            continue;
        }
        const std::size_t start = p;
        while (p < text.size() && (is_alnum(text[p]) || one_of(text[p], "._~+/-"))) {
            ++p;
        }
        if (p - start < 20) {
            continue;
        }
        std::size_t pad = 0;
        while (p < text.size() && text[p] == '=' && pad < 2) {
            ++p;
            ++pad;
        }
        if (p < text.size() && (is_alnum(text[p]) || text[p] == '=')) {
            continue;
        }
        hits.push_back({"bearer", at});
    }
    // A PEM block whose label ends in PRIVATE KEY.
    for (std::size_t at = text.find("-----BEGIN "); at != std::string_view::npos;
         at = text.find("-----BEGIN ", at + 1)) {
        const std::size_t end = text.find("-----", at + 11);
        if (end != std::string_view::npos && is_private_key_label(text.substr(at + 11, end - (at + 11)))) {
            hits.push_back({"pem_private_key", at});
        }
    }
    // An Ed25519 PKCS#8 key: its 21-character opening and the 43 after it.
    constexpr std::string_view kEd25519 = "MC4CAQAwBQYDK2VwBCIEI";
    for (std::size_t at = text.find(kEd25519); at != std::string_view::npos;
         at = text.find(kEd25519, at + 1)) {
        std::size_t n = 0;
        for (std::size_t p = at + kEd25519.size(); p < text.size() && is_base64_char(text[p]); ++p) {
            ++n;
        }
        if (n >= 43) {
            hits.push_back({"ed25519_pkcs8", at});
        }
    }
    // MII..[AQgw]IB then AzCC (a PFX), ADANBgkqhkiG9w0BAQEFAASC (RSA PKCS#8)
    // or AAKCA (RSA PKCS#1).
    for (std::size_t at = text.find("MII"); at != std::string_view::npos;
         at = text.find("MII", at + 1)) {
        if (at + 8 > text.size() || !is_base64_char(text[at + 3]) || !is_base64_char(text[at + 4]) ||
            !one_of(text[at + 5], "AQgw") || text.substr(at + 6, 2) != "IB") {
            continue;
        }
        const std::string_view rest = text.substr(at + 8);
        if (rest.starts_with("AzCC")) {
            hits.push_back({"pkcs12", at});
        } else if (rest.starts_with("ADANBgkqhkiG9w0BAQEFAASC")) {
            hits.push_back({"rsa_pkcs8", at});
        } else if (rest.starts_with("AAKCA")) {
            hits.push_back({"rsa_pkcs1", at});
        }
    }
    // A PFX over 64 KiB: MIM....CAQMwgg.
    for (std::size_t at = text.find("MIM"); at != std::string_view::npos;
         at = text.find("MIM", at + 1)) {
        if (at + 14 <= text.size() && is_base64_char(text[at + 3]) && is_base64_char(text[at + 4]) &&
            is_base64_char(text[at + 5]) && is_base64_char(text[at + 6]) &&
            text.substr(at + 7, 7) == "CAQMwgg") {
            hits.push_back({"pkcs12", at});
        }
    }
    // EC PKCS#8: MIG.AgEAMBMGByqGSM49.
    for (std::size_t at = text.find("MIG"); at != std::string_view::npos;
         at = text.find("MIG", at + 1)) {
        if (at + 20 <= text.size() && is_base64_char(text[at + 3]) &&
            text.substr(at + 4, 16) == "AgEAMBMGByqGSM49") {
            hits.push_back({"ec_pkcs8", at});
        }
    }
    // EC SEC1: P-256, P-384 and P-521 private keys.
    for (const std::string_view opening : {"MHcCAQEEI", "MIGkAgEBBDA", "MIHcAgEBBEIB"}) {
        for (std::size_t at = text.find(opening); at != std::string_view::npos;
             at = text.find(opening, at + 1)) {
            hits.push_back({"ec_sec1", at});
        }
    }
    return hits;
}

// --- the search -----------------------------------------------------------------------

struct Hit {
    std::string output;
    std::string label; // the secret's label, or "shape: <name>"
    std::size_t offset;
};

inline std::vector<Hit> search(const SecretSet& secrets, const Outputs& outputs)
{
    std::vector<Hit> hits;
    for (const Output& output : outputs.items) {
        for (const Secret& secret : secrets.all()) {
            const std::size_t at = output.bytes.find(secret.bytes);
            if (at != std::string::npos) {
                hits.push_back({output.name, secret.label, at});
            }
        }
        for (const ShapeHit& shape : shapes_in(output.bytes)) {
            hits.push_back({output.name, "shape: " + shape.shape, shape.offset});
        }
    }
    return hits;
}

// Fails on every hit, naming the output, the label and the offset, never the
// bytes; REQUIREs that there was something to search.
inline void expect_clean(const SecretSet& secrets, const Outputs& outputs)
{
    REQUIRE_FALSE(outputs.items.empty());
    REQUIRE_FALSE(secrets.all().empty());
    std::size_t bytes = 0;
    for (const Output& output : outputs.items) {
        bytes += output.bytes.size();
    }
    INFO(outputs.items.size() << " output(s), " << bytes << " byte(s), " << secrets.all().size()
                              << " value(s) searched for");
    for (const Hit& hit : search(secrets, outputs)) {
        FAIL_CHECK("secret audit: " << hit.output << " holds " << hit.label << " at byte "
                                    << hit.offset);
    }
}

} // namespace rp::test::secret_audit
