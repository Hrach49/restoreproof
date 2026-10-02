#pragma once

// Reading the three restore targets through Graph (W2.2): what is in the test
// mailbox's Inbox, the RestoreTarget library's root and the test OneDrive's
// /RestoreTarget folder, each item hashed. W3's checker compares the list with
// the expected set; W2.3's `rpworker graph list` prints it. Reads only, and
// never the canaries: before listing a file target one GET checks that the
// drive or folder is a RestoreTarget where the config says, since the Worker
// app's grants alone can't keep it out of the RestoreTest library
// (docs/decisions.md 2026-09-25 and 2026-09-28, W2.2). Those checks are
// rp/target_guard_graph.hpp's, which the restore-target guard runs too (W2.7);
// since W3.2 the mail listing runs its mailbox check first as well.

#include <rp/connector.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_download.hpp>
#include <rp/graph_errors.hpp>
#include <rp/http_client.hpp>
#include <rp/target_guard_graph.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp::graph {

// kMailPrefer, sent as Prefer on every mail call, is rp/graph_client.hpp's
// (the Cleaner's deletes send it too, W3.4).

// A listing follows @odata.nextLink at most this many pages.
inline constexpr int kMaxListPages = 100;

enum class ItemType { mail, sharepoint, onedrive };

// "mail", "sharepoint", "onedrive"; "unknown" for a value outside the enum.
std::string_view to_string(ItemType type) noexcept;

struct FoundItem {
    ItemType type = ItemType::mail;
    // Mail: Graph's ImmutableId message ID. Files: the driveItem ID.
    std::string id;
    std::optional<std::string> name;                // files: the driveItem name
    std::optional<std::string> subject;             // mail ("" is kept as "")
    std::optional<std::string> sender;              // mail: from.emailAddress.address
    std::optional<std::string> sender_name;         // mail: from.emailAddress.name
    std::optional<std::string> sent_at;             // mail: sentDateTime as Graph gives it
    std::optional<std::string> received_at;         // mail: receivedDateTime as Graph gives it
    std::optional<std::string> internet_message_id; // mail: what W3.1 matches mail on
    // createdDateTime (mail and files) and lastModifiedDateTime (files) as Graph
    // gives them: W3.2 compares the newest of two copies by them.
    std::optional<std::string> created_at;
    std::optional<std::string> modified_at;
    // Files: the cTag, which moves when a restore merges a new version into a
    // same-named file (W3.2: a file whose cTag didn't move is an earlier run's).
    std::optional<std::string> ctag;
    // Lower-case hex SHA-256. Mail: text-v1 of body.content. Files: the downloaded
    // bytes. Empty when TargetReaderOptions::hash_items is false.
    std::string sha256;
    // How sha256 was computed: "text-v1" or "bytes"; empty when sha256 is.
    std::string sha256_rule;
    // Files: the bytes downloaded; Graph's size, but for an Office file
    // SharePoint rewrote. Without hash_items, Graph's size as listed.
    std::optional<std::uint64_t> size_bytes;
    // Files: Graph's size as listed, kept when hashing puts the downloaded
    // count in size_bytes. Mail: none.
    std::optional<std::uint64_t> listed_size;
    // Files: the milliseconds the download, the hash and on_file took for this
    // file, by TargetReaderOptions::clock (W3.2's per-item ms). Mail, and files
    // without hash_items: 0. on_file sees it still 0: it is set when on_file returns.
    std::int64_t read_ms = 0;

    bool operator==(const FoundItem&) const = default;
};

// Whether a nextLink's path (lower case, split at '/') names the target listed.
using NextLinkRule = std::function<bool(const std::vector<std::string>& path)>;

struct TargetReaderOptions {
    // The reader's own lines (counts, skipped items); null: spdlog::default_logger().
    std::shared_ptr<spdlog::logger> logger;
    // Whether each item is hashed: each file downloaded, each mail's body asked
    // for. False (`rpworker graph list` without --hash, W2.3): nothing is
    // downloaded, the download client is never called, the mail listing leaves
    // body out of $select and nothing checks a body Graph sends anyway; every
    // sha256 and sha256_rule stays empty and a file's size_bytes is Graph's
    // size. The guards run the same either way.
    bool hash_items = true;
    DownloadOptions download;
    // Called with each file's bytes after they were size-checked and hashed,
    // before the next download; the bytes are gone after it returns. W3.2
    // computes office-v1 here. What it throws is thrown as it is. Never called
    // without hash_items.
    std::function<void(const FoundItem&, std::string_view bytes)> on_file;
    // Asked of each file once it is listed, before anything is downloaded:
    // whether to download and hash it (W3.2 review: the after read reads only
    // this run's copies of expected files). A file it rejects is listed as
    // without hash_items: Graph's size in size_bytes, no sha256, read_ms 0,
    // on_file not called, nothing downloaded. Null: every file is hashed. Never
    // asked without hash_items, nor for a mail. What it throws is thrown as it is.
    std::function<bool(const FoundItem&)> hash_file;
    // What FoundItem::read_ms is measured by; null: std::chrono::steady_clock::now.
    std::function<std::chrono::steady_clock::time_point()> clock;
};

// Lists and hashes what is in the three restore targets. Items come in
// Graph's order; an empty location is an empty vector, never an error.
// Subfolders and items that aren't files are skipped and logged (restores land
// files in the root). Every Graph error keeps its W2.1 type: a missing mailbox,
// drive or folder is a NotFoundError (status `error`, never `fail`); a failed
// download is an error too, never an item quietly dropped.
// `graph` and `download` must outlive the reader. Not thread-safe: one listing
// at a time.
class TargetReader {
public:
    // Sends nothing. The IDs' shapes were checked by RestoreTargets::from_config
    // (rp/config.hpp: kGraphSiteIdRule and the others).
    TargetReader(GraphClient& graph, IHttpClient& download, connector::RestoreTargets targets,
                 TargetReaderOptions options = {});

    // The test mailbox's Inbox, after the guard's mailbox check
    // (check_restore_mailbox): a 403 on the Inbox is a WrongTargetError and
    // nothing is listed.
    std::vector<FoundItem> list_mail();
    std::vector<FoundItem> list_sharepoint(); // the RestoreTarget library's root
    std::vector<FoundItem> list_onedrive();   // the test OneDrive's /RestoreTarget folder
    // Mail, then SharePoint, then OneDrive; the first error ends it.
    std::vector<FoundItem> list_all();
    // The entries the last list_mail, list_sharepoint or list_onedrive call
    // left out: folders and entries that aren't files (W3.4: `graph list`
    // says how many, so a target showing zero items really holds nothing).
    // 0 after list_mail, which leaves nothing out, and before any call;
    // list_all's is its OneDrive listing's.
    std::size_t unlisted() const noexcept;

private:
    struct FileTarget {
        ItemType type;
        const Grant* grant;
        std::string drive_id;
        std::string children_path;
        std::string location; // "the RestoreTarget library", "the test OneDrive folder"
        NextLinkRule next_rule;
    };

    std::vector<FoundItem> list_files(const FileTarget& target);
    std::chrono::steady_clock::time_point now() const;
    void log(spdlog::level::level_enum level, const std::string& line) const;

    GraphClient& graph_;
    IHttpClient& download_;
    connector::RestoreTargets targets_;
    TargetReaderOptions options_;
    std::string tenant_host_; // test_site_id's host, lower case
    std::size_t unlisted_ = 0;
};

} // namespace rp::graph
