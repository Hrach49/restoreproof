// W3.4 (#39) live check: the Cleaner empties the lab's three restore targets,
// and afterwards each one lists no entry at all, folders included (the
// Done-when's "zero items and no entries left unlisted").
//
// The targets are usually empty already (every `rpworker restore` cleans
// before and after), so the test first seeds one item of its own in each: a
// small rp-probe-<uuid>.txt in the RestoreTarget library's root, one in
// alice's /RestoreTarget folder, and a message with subject rp-probe-<uuid>
// created in the restoretest Inbox (a draft there, which the Cleaner lists
// like any Inbox mail). The Cleaner then has real deletes to make, and the
// doubled deletes below an item already gone to see. The seeds are sent by the test
// itself, with a token of its own and cpr: GraphClient has no create member
// (its only write is remove(), for the Cleaner) and rp::IHttpClient has no
// PUT. Before any seed is sent, the configured IDs are checked against every
// canary location of lab/seed-manifest.json, then checked for shape and each
// target resolved through the target guard's own Graph checks (the ones the
// Cleaner's resolve() runs); the three seed paths are built only from what
// those checks established (tests/live_seed.hpp), so a configured ID is never
// trusted alone. Any refusal fails the test before the first write.
//
// It WRITES to the lab tenant (it creates and deletes in the restore
// targets): skipped unless both RP_LIVE=1 and RP_LIVE_RESTORE=1, like the
// live restore test, so a normal RP_LIVE=1 run stays read-only. It takes the
// run mutex first, as `rpworker restore` does, so it never touches a running
// restore's copies. docs/testing.md, "Live restore (writes to the lab
// tenant)".
//
// Environment: the Graph variables of the other live tests (docs/testing.md,
// "Live tests"), plus RP_LIVE_RESTORE=1. A folder or other entry the Cleaner
// skips is left for the owner and fails the last check: remove it by hand.
//
// W3.4 point 9: the Cleaner's first file DELETE and first mail
// permanentDelete are each sent twice, and the second answer is what the
// Cleaner sees: it counts that item `gone`. For the file that answer is
// Graph's 404 itemNotFound; for the mail it is 403 ErrorCannotDeleteObject
// (seen live on 2026-10-02), which remove() follows with one check, is the
// message gone: a GET of the message's parentFolderId (live it answered 200,
// the purged message in Recoverable Items) and a GET of the Purges folder's
// ID; only a byte-for-byte match (or a 404) makes it gone, the Inbox's ID
// leaves the 403, any other folder is an error (W3.4 build notes point 15).
// With RP_LIVE_RECORD_DIR set to a new or empty folder, every Graph exchange
// of the Cleaner and the final listings is recorded there as `rpworker
// restore --record` would (rp::FixtureRecorder, under graph/), the second
// answers and those GETs included; the first answer of each doubled send is
// not (the wrapper sits inside the recorder). The seeds are not recorded.

#include "../src/command_config.hpp"
#include "graph_live_lab.hpp"
#include "live_seed.hpp"
#include "test_support.hpp"

#include <rp/canary_manifest.hpp>
#include <rp/cleaner.hpp>
#include <rp/client_assertion.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/graph_client.hpp>
#include <rp/run_lock.hpp>
#include <rp/sample_selector.hpp>
#include <rp/secrets.hpp>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <stdexcept>
#include <string>

namespace {

using nlohmann::json;

// Sends the first file DELETE and the first mail permanentDelete through
// `inner` twice and returns the second answer when the first was a 204;
// every other request goes through once. The write still comes only from the
// Cleaner, on an item it listed. Runs on the test's thread only.
class SendFirstDeleteTwice final : public rp::IHttpClient {
public:
    explicit SendFirstDeleteTwice(std::unique_ptr<rp::IHttpClient> inner)
        : inner_(std::move(inner))
    {
    }

    rp::HttpResponse send(const rp::HttpRequest& request) override
    {
        const bool file = request.method == rp::HttpMethod::del;
        const bool mail = request.method == rp::HttpMethod::post &&
                          request.url.ends_with("/permanentDelete");
        bool& done = file ? file_done_ : mail_done_;
        if (!(file || mail) || done) {
            return inner_->send(request);
        }
        done = true;
        const rp::HttpResponse first = inner_->send(request);
        if (first.status != 204) {
            return first;
        }
        ++doubled_;
        return inner_->send(request);
    }

    // Deletes sent twice after a 204.
    std::size_t doubled() const noexcept { return doubled_; }

private:
    std::unique_ptr<rp::IHttpClient> inner_;
    bool file_done_ = false;
    bool mail_done_ = false;
    std::size_t doubled_ = 0;
};

// How many entries the first page of `path` lists, whatever they are.
std::size_t entries_at(rp::graph::GraphClient& client, const std::string& path,
                       const rp::graph::Grant& grant, const rp::HttpHeaders& headers = {})
{
    const json page = client.get_json(path, grant, headers);
    return page.at("value").size();
}

// ---- Seeding: one item of the test's own in each restore target ------------

const std::string kGraphV1 = "https://graph.microsoft.com/v1.0";
const std::string kSeedText =
    "rp-probe: seeded by the live cleanup test; the Cleaner deletes it.\n";

std::string ascii_lower(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

// A random UUID v4, lower case: the seeds' names are new on every run.
std::string random_uuid()
{
    std::random_device device;
    std::array<unsigned char, 16> bytes{};
    for (unsigned char& byte : bytes) {
        byte = static_cast<unsigned char>(device() & 0xFFu);
    }
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0Fu) | 0x40u);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3Fu) | 0x80u);
    std::string out;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            out += '-';
        }
        std::array<char, 3> hex{};
        std::snprintf(hex.data(), hex.size(), "%02x", static_cast<unsigned>(bytes[i]));
        out += hex.data();
    }
    return out;
}

// Why the config's restore-target IDs could reach a canary location of
// lab/seed-manifest.json, or "" when none can: the manifest's own check
// (sampling::check_manifest, which throws), then every canary's mailbox,
// SharePoint drive and folder against the IDs the seed paths are built from.
// (alice's OneDrive drive holds both her canary folder and the restore
// target, so for OneDrive only the folder is compared.)
std::string canary_clash(const rp::Config& config)
{
    const std::filesystem::path path =
        std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "seed-manifest.json";
    rp::sampling::check_manifest(rp::sampling::load_canary_manifest(path),
                                 rp::connector::RestoreTargets::from_config(config),
                                 config.graph_tenant_id);
    std::ifstream in(path, std::ios::binary);
    const json manifest = json::parse(std::string{std::istreambuf_iterator<char>(in), {}});
    std::set<std::string> mailboxes;
    std::set<std::string> drives;
    std::set<std::string> folders;
    for (const json& entry : manifest.at("entries")) {
        const json& location = entry.at("location");
        if (location.contains("mailbox")) {
            mailboxes.insert(ascii_lower(location.at("mailbox").get<std::string>()));
        }
        if (entry.at("kind") == "sharepoint_file" && location.contains("drive_id")) {
            drives.insert(location.at("drive_id").get<std::string>());
        }
        if (location.contains("folder_id")) {
            folders.insert(location.at("folder_id").get<std::string>());
        }
    }
    if (mailboxes.empty() || drives.empty() || folders.empty()) {
        return "the manifest names no canary mailbox, library or folder to compare with";
    }
    if (mailboxes.contains(ascii_lower(config.test_mailbox))) {
        return "the restore mailbox is a canary mailbox";
    }
    if (drives.contains(config.test_library_id)) {
        return "the restore library is a canary library";
    }
    if (folders.contains(config.test_onedrive_folder_id)) {
        return "the OneDrive restore folder is a canary folder";
    }
    return "";
}

cpr::SslOptions verifying_tls()
{
    cpr::SslOptions ssl;
    ssl.verify_peer = true;
    ssl.verify_host = true;
    return ssl;
}

// An app-only Graph token of the test's own (never printed), from the Worker
// app's certificate: the seeds don't go through GraphClient.
std::string seed_token(const rp::Config& config, const rp::Secrets& secrets)
{
    const rp::graph::ClientCertificate certificate =
        rp::graph::certificate_from_secrets(secrets, std::chrono::system_clock::now());
    cpr::Session session;
    session.SetUrl(cpr::Url{rp::graph::entra_token_url(config.graph_tenant_id)});
    session.SetPayload(cpr::Payload{
        {"client_id", config.graph_client_id},
        {"scope", std::string{rp::graph::kGraphScope}},
        {"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
        {"client_assertion",
         rp::graph::make_client_assertion(certificate, config.graph_tenant_id,
                                          config.graph_client_id,
                                          std::chrono::system_clock::now())},
        {"grant_type", "client_credentials"}});
    session.SetTimeout(cpr::Timeout{std::chrono::seconds{60}});
    session.SetRedirect(cpr::Redirect{0L, false, false, cpr::PostRedirectFlags::NONE});
    session.SetSslOptions(verifying_tls());
    const cpr::Response response = session.Post();
    if (response.status_code != 200) {
        // Only the status and curl's own error: the body is never quoted.
        throw std::runtime_error("seed token: HTTP " + std::to_string(response.status_code) +
                                 " " + response.error.message);
    }
    return json::parse(response.text).at("access_token").get<std::string>();
}

// Sends one seed and returns Graph's reply, or nullopt (printed why) unless
// it was a 201 with a JSON object. `path` is one of the three of
// live_seed::resolve_seed_paths, never anything else.
std::optional<json> send_seed(const std::string& token, const std::string& method,
                              const std::string& path, const std::string& content_type,
                              const std::string& body, const cpr::Header& extra = {})
{
    cpr::Session session;
    session.SetUrl(cpr::Url{kGraphV1 + path});
    cpr::Header header{{"Authorization", "Bearer " + token}, {"Content-Type", content_type}};
    for (const auto& [name, value] : extra) {
        header[name] = value;
    }
    session.SetHeader(header);
    session.SetBody(cpr::Body{body});
    session.SetTimeout(cpr::Timeout{std::chrono::seconds{60}});
    session.SetRedirect(cpr::Redirect{0L, false, false, cpr::PostRedirectFlags::NONE});
    session.SetSslOptions(verifying_tls());
    const cpr::Response response = method == "PUT" ? session.Put() : session.Post();
    std::cout << "seed " << method << " " << path << ": HTTP " << response.status_code << "\n";
    if (response.status_code != 201) {
        // Graph's error body holds no credential.
        std::cout << "  " << response.error.message << " " << response.text.substr(0, 500)
                  << "\n";
        return std::nullopt;
    }
    json reply = json::parse(response.text, nullptr, false);
    if (!reply.is_object()) {
        return std::nullopt;
    }
    return reply;
}

// The seeded file is where the test put it: its name, in its drive, and
// (when `parent_id` is set) directly in that folder.
bool seeded_file_in_place(const std::optional<json>& reply, const std::string& name,
                          const std::string& drive_id, const std::string& parent_id = {})
{
    return reply && reply->value("name", "") == name && reply->contains("parentReference") &&
           reply->at("parentReference").is_object() &&
           reply->at("parentReference").value("driveId", "") == drive_id &&
           (parent_id.empty() || reply->at("parentReference").value("id", "") == parent_id);
}

} // namespace

TEST_CASE("live cleanup: the Cleaner empties the three restore targets with folders and all",
          "[live][writes]")
{
    if (rp::test::get_env("RP_LIVE") != std::optional<std::string>{"1"} ||
        rp::test::get_env("RP_LIVE_RESTORE") != std::optional<std::string>{"1"}) {
        SKIP("writes to the lab tenant: set both RP_LIVE=1 and RP_LIVE_RESTORE=1 to run");
    }
    const std::unique_ptr<rp::RunLock> lock = rp::try_take_restore_targets_lock();
    REQUIRE(lock != nullptr); // another RestoreProof run is using the restore targets

    const rp::Config config = rp::test::graph_live::live_config();
    auto logger = std::make_shared<spdlog::logger>(
        "live_cleanup", std::make_shared<spdlog::sinks::ostream_sink_mt>(std::cout));
    logger->set_level(spdlog::level::info);
    const rp::Secrets secrets = rp::load_secrets_from_env();

    // Seed one item of the test's own in each target, so the Cleaner has
    // something to delete even when the targets are empty. Never anywhere
    // else: the IDs are checked against the canaries first, then for shape,
    // then each target is resolved through the guard's Graph checks (on a
    // client of its own, so the recording below holds only the Cleaner's
    // exchanges), and the paths are built from what they established. A
    // refusal stops the test before any write. A failed seed fails the test
    // but doesn't stop the clean, which removes the seeds that were made.
    const std::string clash = canary_clash(config);
    INFO(clash);
    REQUIRE(clash.empty());
    const std::string probe = "rp-probe-" + random_uuid();
    const std::string file_name = probe + ".txt";
    const std::unique_ptr<rp::IHttpClient> resolve_http =
        rp::graph::make_graph_http_client(logger);
    rp::graph::GraphClientOptions resolve_options;
    resolve_options.logger = logger;
    rp::graph::GraphClient resolve_client(
        *resolve_http, config.graph_tenant_id, config.graph_client_id,
        rp::graph::certificate_from_secrets(secrets, std::chrono::system_clock::now(), logger),
        resolve_options);
    const rp::test::live_seed::SeedPaths paths =
        rp::test::live_seed::resolve_seed_paths(resolve_client, config, probe);
    const std::string token = seed_token(config, secrets);
    const std::optional<json> library_seed =
        send_seed(token, "PUT", paths.library, "application/octet-stream", kSeedText);
    const std::optional<json> onedrive_seed =
        send_seed(token, "PUT", paths.onedrive, "application/octet-stream", kSeedText);
    const json mail_body = {{"subject", probe},
                            {"body", {{"contentType", "text"}, {"content", kSeedText}}}};
    const std::optional<json> mail_seed =
        send_seed(token, "POST", paths.mail, "application/json", mail_body.dump(),
                  cpr::Header{{"Prefer", std::string{rp::graph::kMailPrefer}}});
    CHECK(seeded_file_in_place(library_seed, file_name, paths.library_drive_id));
    CHECK(seeded_file_in_place(onedrive_seed, file_name, paths.onedrive_drive_id,
                               paths.onedrive_folder_id));
    CHECK((mail_seed && mail_seed->value("subject", "") == probe));

    const std::optional<std::string> record_dir = rp::test::get_env("RP_LIVE_RECORD_DIR");
    const std::shared_ptr<rp::FixtureRecorder> recorder =
        record_dir && !record_dir->empty()
            ? rp::open_recording(*record_dir, "cleaner live test", secrets)
            : nullptr;
    auto twice = std::make_unique<SendFirstDeleteTwice>(rp::graph::make_graph_http_client(logger));
    const SendFirstDeleteTwice& doubler = *twice;
    const std::unique_ptr<rp::IHttpClient> http = rp::recorded(std::move(twice), recorder, "graph");
    rp::graph::GraphClientOptions options;
    options.logger = logger;
    rp::graph::GraphClient client(
        *http, config.graph_tenant_id, config.graph_client_id,
        rp::graph::certificate_from_secrets(secrets, std::chrono::system_clock::now(), logger),
        options);
    rp::graph::CleanerOptions cleaner_options;
    cleaner_options.logger = logger;
    rp::graph::Cleaner cleaner(client, rp::connector::RestoreTargets::from_config(config),
                               cleaner_options);

    const rp::graph::CleanupResult result = cleaner.clean(rp::graph::CleanupWhen::after_run);
    std::cout << "cleanup " << to_json(result).dump() << "\n";
    CHECK(result.mail.error_code.empty());
    CHECK(result.sharepoint.error_code.empty());
    CHECK(result.onedrive.error_code.empty());
    CHECK(result.ok());
    // Each seed was found and removed: deleted (204), or gone for the one
    // whose delete was sent twice.
    CHECK(result.mail.found >= 1);
    CHECK(result.sharepoint.found >= 1);
    CHECK(result.onedrive.found >= 1);
    CHECK(result.mail.deleted + result.mail.gone >= 1);
    CHECK(result.sharepoint.deleted + result.sharepoint.gone >= 1);
    CHECK(result.onedrive.deleted + result.onedrive.gone >= 1);
    // With the seeds there, the first file DELETE and the first mail
    // permanentDelete are both sent twice, and each second answer (the
    // file's 404, the mail's 403 ErrorCannotDeleteObject with the message
    // found in Recoverable Items' Purges) was counted gone, not an error.
    std::cout << "deletes sent twice: " << doubler.doubled() << "\n";
    CHECK(doubler.doubled() == 2);
    CHECK(result.mail.gone >= 1);
    CHECK(result.sharepoint.gone + result.onedrive.gone >= 1);
    if (recorder) {
        std::cout << "recorded " << recorder->written() << " exchange(s) in "
                  << recorder->dir().string() << "\n";
        CHECK(recorder->problems().empty());
    }

    // Every entry, not only what the Cleaner may delete: nothing at all left.
    CHECK(entries_at(client,
                     "/users/" + config.test_mailbox +
                         "/mailFolders/inbox/messages?$top=1&$select=id",
                     rp::graph::kMailGrant,
                     {{"Prefer", std::string{rp::graph::kMailPrefer}}}) == 0);
    CHECK(entries_at(client,
                     "/drives/" + config.test_library_id + "/root/children?$top=1&$select=id",
                     rp::graph::kSitesReadGrant) == 0);
    CHECK(entries_at(client,
                     "/drives/" + config.test_onedrive_drive_id + "/items/" +
                         config.test_onedrive_folder_id + "/children?$top=1&$select=id",
                     rp::graph::kOneDriveGrant) == 0);
}
