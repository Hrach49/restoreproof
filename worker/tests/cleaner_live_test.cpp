// W3.4 (#39) live check: the Cleaner empties the lab's three restore targets,
// and afterwards each one lists no entry at all, folders included (the
// Done-when's "zero items and no entries left unlisted").
//
// It WRITES to the lab tenant (it deletes in the restore targets): skipped
// unless both RP_LIVE=1 and RP_LIVE_RESTORE=1, like the live restore test, so
// a normal RP_LIVE=1 run stays read-only. It takes the run mutex first, as
// `rpworker restore` does, so it never deletes a running restore's copies.
// docs/testing.md, "Live restore (writes to the lab tenant)".
//
// Environment: the Graph variables of the other live tests (docs/testing.md,
// "Live tests"), plus RP_LIVE_RESTORE=1. A folder or other entry the Cleaner
// skips is left for the owner and fails the last check: remove it by hand.
//
// W3.4 point 9: the Cleaner's first file DELETE and first mail
// permanentDelete are each sent twice, and the second answer (Graph's 404 for
// an item already gone) is what the Cleaner sees: it counts that item `gone`.
// With RP_LIVE_RECORD_DIR set to a new or empty folder, every Graph exchange
// is recorded there as `rpworker restore --record` would (rp::FixtureRecorder,
// under graph/), those 404s included, for the w34-*-404-* fixtures.

#include "../src/command_config.hpp"
#include "graph_live_lab.hpp"
#include "test_support.hpp"

#include <rp/cleaner.hpp>
#include <rp/client_assertion.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/graph_client.hpp>
#include <rp/run_lock.hpp>
#include <rp/secrets.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <iostream>
#include <memory>
#include <optional>
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

} // namespace

TEST_CASE("live cleanup: the Cleaner empties the three restore targets, folders and all",
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
    // Each delete sent twice got Graph's 404 the second time: gone, not an error.
    std::cout << "deletes sent twice: " << doubler.doubled() << "\n";
    CHECK(result.mail.gone + result.sharepoint.gone + result.onedrive.gone >= doubler.doubled());
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
