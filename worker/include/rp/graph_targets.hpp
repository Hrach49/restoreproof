#pragma once

// Reading the three restore targets through Graph (W2.2): what is in the test
// mailbox's Inbox, the RestoreTarget library's root and the test OneDrive's
// /RestoreTarget folder, each item hashed. W3's checker compares the list with
// the expected set; W2.3's `rpworker graph list` prints it. Reads only, and
// never the canaries: before listing a file target one GET checks that the
// drive or folder is a RestoreTarget where the config says, since the Worker
// app's grants alone can't keep it out of the RestoreTest library
// (docs/decisions.md 2026-09-25 and 2026-09-28, W2.2).

#include <rp/connector.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_download.hpp>
#include <rp/graph_errors.hpp>
#include <rp/http_client.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp::graph {

// Sent as Prefer on every mail call, as the seeder does (lab/README.md,
// "text-v1"): bodies as text, IDs that survive a move.
inline constexpr std::string_view kMailPrefer =
    "outlook.body-content-type=\"text\", IdType=\"ImmutableId\"";
// The name both file targets must have (docs/decisions.md 2026-09-25).
inline constexpr std::string_view kRestoreTargetName = "RestoreTarget";
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
    std::optional<std::string> received_at;         // mail: receivedDateTime as Graph gives it
    std::optional<std::string> internet_message_id; // mail: what W3.1 matches mail on
    // Lower-case hex SHA-256. Mail: text-v1 of body.content. Files: the downloaded bytes.
    std::string sha256;
    // How sha256 was computed: "text-v1" or "bytes".
    std::string sha256_rule;
    std::optional<std::uint64_t> size_bytes; // files: bytes downloaded (== Graph's size)

    bool operator==(const FoundItem&) const = default;
};

// A guard refusal: the configured drive or folder is not a RestoreTarget of
// the test site or OneDrive, the canaries' RestoreTest included. Nothing was
// listed; the run's status is `error`.
class WrongTargetError : public GraphError {
public:
    using GraphError::GraphError;
};

struct TargetReaderOptions {
    // The reader's own lines (counts, skipped items); null: spdlog::default_logger().
    std::shared_ptr<spdlog::logger> logger;
    DownloadOptions download;
    // Called with each file's bytes after they were size-checked and hashed,
    // before the next download; the bytes are gone after it returns. W3.2
    // computes office-v1 here. What it throws is thrown as it is.
    std::function<void(const FoundItem&, std::string_view bytes)> on_file;
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
    // Throws rp::ConfigError (its key named) at once if a configured ID can't
    // be a Graph ID: test_site_id "<tenant>.sharepoint.com,<site GUID>,<web
    // GUID>", test_library_id and test_onedrive_drive_id "b!" and a drive ID,
    // test_onedrive_folder_id an item ID. Sends nothing.
    TargetReader(GraphClient& graph, IHttpClient& download, connector::RestoreTargets targets,
                 TargetReaderOptions options = {});

    std::vector<FoundItem> list_sharepoint(); // the RestoreTarget library's root
    std::vector<FoundItem> list_onedrive();   // the test OneDrive's /RestoreTarget folder

private:
    struct FileTarget {
        ItemType type;
        const Grant* grant;
        std::string drive_id;
        std::string children_path;
        std::string location; // "the RestoreTarget library", "the test OneDrive folder"
    };

    void check_library();
    void check_onedrive_folder();
    std::vector<FoundItem> list_files(const FileTarget& target);
    void log(spdlog::level::level_enum level, const std::string& line) const;

    GraphClient& graph_;
    IHttpClient& download_;
    connector::RestoreTargets targets_;
    TargetReaderOptions options_;
    std::string tenant_host_; // test_site_id's host, lower case
    std::string site_guid_;   // test_site_id's site collection GUID
    std::string web_guid_;    // test_site_id's web GUID
};

} // namespace rp::graph
