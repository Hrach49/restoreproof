#include <rp/graph_targets.hpp>

#include <rp/config.hpp>
#include <rp/redact.hpp>
#include <rp/sha256.hpp>
#include <rp/text_v1.hpp>

#include "json_fields.hpp"
#include "office_files.hpp"
#include "text_util.hpp"
#include "uuid.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <iterator>
#include <set>
#include <utility>

namespace rp::graph {

namespace {

using nlohmann::json;

// cTag and the two times: W3.2's checker tells this run's copies from an
// earlier run's by them (docs/decisions.md 2026-10-01, W3.2).
constexpr std::string_view kChildrenQuery =
    "?$select=id,name,size,cTag,createdDateTime,lastModifiedDateTime,file,folder&$top=200";
constexpr std::string_view kMailSelect =
    "?$select=id,subject,from,sentDateTime,receivedDateTime,createdDateTime,internetMessageId";

// 1..max_size of ASCII letters, digits and the characters in `extra`.
bool is_id(std::string_view text, std::string_view extra, std::size_t max_size)
{
    return !text.empty() && text.size() <= max_size &&
           std::all_of(text.begin(), text.end(), [extra](char c) {
               const auto byte = static_cast<unsigned char>(c);
               return byte < 0x80 && (std::isalnum(byte) || extra.find(c) != std::string_view::npos);
           });
}

// The resource a listing URL names, to check a nextLink against its target's
// rule: the path after Graph's v1.0 root (list_pages passes only such URLs), up
// to the query, percent-decoded, "seg('v')" and "seg(v)" as "seg/v", lower
// case, split at '/'.
std::vector<std::string> resource_path(std::string_view url)
{
    if (url.starts_with(kGraphBaseUrl)) {
        url.remove_prefix(kGraphBaseUrl.size());
    }
    const std::string path = percent_decode(url.substr(0, url.find('?')));
    std::string out;
    std::size_t start = 0;
    for (;;) {
        const std::size_t end = path.find('/', start);
        std::string_view segment =
            std::string_view{path}.substr(start, end == std::string::npos ? end : end - start);
        const std::size_t open = segment.find('(');
        if (open != std::string_view::npos && segment.ends_with(')')) {
            std::string_view value = segment.substr(open + 1, segment.size() - open - 2);
            if (value.size() >= 2 && value.front() == '\'' && value.back() == '\'') {
                value = value.substr(1, value.size() - 2);
            }
            out += std::string{segment.substr(0, open)} + "/" + std::string{value};
        } else {
            out += segment;
        }
        if (end == std::string::npos) {
            break;
        }
        out += '/';
        start = end + 1;
    }
    // The path after the root starts with '/': no empty first segment.
    const std::string folded = ascii_lower(std::string_view{out}.substr(1));
    std::vector<std::string> segments;
    for (std::size_t at = 0;;) {
        const std::size_t slash = folded.find('/', at);
        segments.push_back(folded.substr(at, slash == std::string::npos ? slash : slash - at));
        if (slash == std::string::npos) {
            return segments;
        }
        at = slash + 1;
    }
}

// Every page of a listing that starts at `first`, following @odata.nextLink
// while `next_rule` takes the resource_path() of each link.
std::vector<json> list_pages(GraphClient& graph, const std::string& first, const Grant& grant,
                             const HttpHeaders& headers, const std::string& what,
                             const NextLinkRule& next_rule)
{
    const std::string first_url = std::string{kGraphBaseUrl} + first;
    const std::string prefix = std::string{kGraphBaseUrl} + "/";
    std::set<std::string> fetched{first_url};
    std::vector<json> pages;
    std::string url = first_url;
    for (;;) {
        json page = graph.get_json(url, grant, headers);
        const auto value = page.find("value");
        if (value == page.end() || !value->is_array()) {
            throw GraphError("Graph's reply listing " + what + " has no \"value\" array");
        }
        const auto link = page.find("@odata.nextLink");
        std::optional<json> next_link;
        if (link != page.end()) {
            next_link = *link;
        }
        pages.push_back(std::move(page));
        if (!next_link) {
            return pages;
        }
        const std::string next = next_link->is_string() ? next_link->get<std::string>() : "";
        // Graph sends absolute links. Anything else is refused here, a relative one
        // too: GraphClient would put its v1.0 root in front of it and send it.
        if (!next.starts_with(prefix) || fetched.contains(next) || !next_rule(resource_path(next))) {
            throw GraphError("Graph's reply listing " + what + " has a bad @odata.nextLink");
        }
        if (pages.size() >= static_cast<std::size_t>(kMaxListPages)) {
            throw GraphError("listing " + what + " went past " + std::to_string(kMaxListPages) +
                             " pages; the Worker stops there");
        }
        fetched.insert(next);
        url = next;
    }
}

std::optional<std::string> optional_string(const json& object, std::string_view key)
{
    const std::string* value = string_at(object, key);
    return value ? std::optional<std::string>{*value} : std::nullopt;
}

// The "id" of an entry Graph listed, if it may go in a URL path (Exchange's
// IDs end in '=').
std::string graph_id(const json& entry, const std::string& what)
{
    const std::string* id = string_at(entry, "id");
    if (id == nullptr || !is_id(*id, "!-_=", 512)) {
        throw GraphError("Graph returned " + what + " with an ID the Worker won't put in a URL");
    }
    return *id;
}

// A nextLink's path may name the same target in another form than the first
// request did (review of W2.2): Graph documents the link as opaque. These take
// the forms that still name the guarded target, and nothing that could reach
// another folder of the same drive (alice's canaries share hers).

// users/{the mailbox, or an object ID}/mailfolders/inbox/messages
bool is_inbox_path(const std::vector<std::string>& path, const std::string& mailbox)
{
    return path.size() == 5 && path[0] == "users" &&
           (path[1] == ascii_lower(mailbox) || is_uuid(path[1])) && path[2] == "mailfolders" &&
           path[3] == "inbox" && path[4] == "messages";
}

// drives/{drive}/root/children, or drives/{drive}/items/{an item ID}/children
bool is_library_root_path(const std::vector<std::string>& path, const std::string& drive)
{
    const bool drive_ok = path.size() >= 4 && path[0] == "drives" && path[1] == ascii_lower(drive);
    return drive_ok && ((path.size() == 4 && path[2] == "root" && path[3] == "children") ||
                        (path.size() == 5 && path[2] == "items" && is_graph_item_id(path[3]) &&
                         path[4] == "children"));
}

// drives/{drive}/items/{folder}/children: that folder only.
bool is_folder_path(const std::vector<std::string>& path, const std::string& drive,
                    const std::string& folder)
{
    return path.size() == 5 && path[0] == "drives" && path[1] == ascii_lower(drive) &&
           path[2] == "items" && path[3] == ascii_lower(folder) && path[4] == "children";
}

} // namespace

std::string_view to_string(ItemType type) noexcept
{
    switch (type) {
    case ItemType::mail:
        return "mail";
    case ItemType::sharepoint:
        return "sharepoint";
    case ItemType::onedrive:
        return "onedrive";
    }
    return "unknown";
}

TargetReader::TargetReader(GraphClient& graph, IHttpClient& download,
                           connector::RestoreTargets targets, TargetReaderOptions options)
    : graph_(graph), download_(download), targets_(std::move(targets)), options_(std::move(options))
{
    // RestoreTargets::from_config checked every ID's shape, the site ID's too.
    tenant_host_ = parse_graph_site_id(targets_.site_id()).value().host;
}

std::chrono::steady_clock::time_point TargetReader::now() const
{
    return options_.clock ? options_.clock() : std::chrono::steady_clock::now();
}

void TargetReader::log(spdlog::level::level_enum level, const std::string& line) const
{
    // May be null: spdlog::drop_all() and shutdown() clear the default logger.
    const std::shared_ptr<spdlog::logger> logger =
        options_.logger ? options_.logger : spdlog::default_logger();
    if (logger && logger->should_log(level)) {
        logger->log(level, "{}", redact(line));
    }
}

std::vector<FoundItem> TargetReader::list_files(const FileTarget& target)
{
    const std::string& location = target.location;
    const std::vector<json> pages =
        list_pages(graph_, target.children_path, *target.grant, {}, location, target.next_rule);
    std::vector<FoundItem> items;
    for (const json& page : pages) {
        for (const json& entry : page.at("value")) {
            const std::string id = graph_id(entry, "an item in " + location);
            // Restores land files in the root (docs/decisions.md 2026-09-28, W2.2).
            if (entry.contains("folder")) {
                log(spdlog::level::info, "skipped a folder in " + location + ": " + id +
                                             " (restores land files in the root; subfolders "
                                             "aren't read)");
                continue;
            }
            if (!entry.contains("file")) {
                log(spdlog::level::warn,
                    "skipped an item that is not a file in " + location + ": " + id);
                continue;
            }
            const std::string* name = string_at(entry, "name");
            if (name == nullptr) {
                throw GraphError("Graph's reply listing " + location + " has a file without a name");
            }
            const auto size = entry.find("size");
            if (size == entry.end() || !size->is_number_unsigned()) {
                throw GraphError("Graph's reply listing " + location +
                                 " has a file without a size: " + id);
            }
            FoundItem item;
            item.type = target.type;
            item.id = id;
            item.name = *name;
            item.size_bytes = size->get<std::uint64_t>();
            item.listed_size = item.size_bytes;
            item.ctag = optional_string(entry, "cTag");
            item.created_at = optional_string(entry, "createdDateTime");
            item.modified_at = optional_string(entry, "lastModifiedDateTime");
            // Listed only: not hashing, or a file the caller doesn't compare
            // (W3.2 review: an earlier run's leftover is never downloaded).
            if (!options_.hash_items || (options_.hash_file && !options_.hash_file(item))) {
                items.push_back(std::move(item));
                continue;
            }
            // SharePoint rewrites Office files, so their bytes may differ
            // from the size listed (office-v1; review of W2.2; one rule, W3.1).
            const bool office = is_rewritten_office_file(*name);
            const auto started = now();
            const std::string bytes = download_item(
                graph_, download_, *target.grant, tenant_host_, target.drive_id, id,
                *item.size_bytes, office ? SizeCheck::up_to_limit : SizeCheck::exact,
                location + " item " + id, options_.download);
            item.sha256 = sha256_hex(bytes);
            item.sha256_rule = "bytes";
            item.size_bytes = bytes.size();
            if (options_.on_file) {
                options_.on_file(item, bytes);
            }
            item.read_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(now() - started).count();
            items.push_back(std::move(item));
        }
    }
    log(spdlog::level::info,
        "listed " + std::to_string(items.size()) + " item(s) in " + target.location);
    return items;
}

namespace {

// text-v1 of a listed message's body, which comes in the listing (Prefer asks
// for text): no GET per mail.
std::string mail_body_sha256(const json& message, const std::string& location)
{
    const auto found = message.find("body");
    const json none;
    const json& body = found == message.end() ? none : *found;
    const std::string* type = string_at(body, "contentType");
    if (type == nullptr || !ascii_iequals(*type, "text")) {
        throw GraphError("Graph returned the body of a message in the test mailbox as \"" +
                         (type ? one_line(*type, 20) : std::string{"(none)"}) +
                         "\", not text, although the Worker asked for text; its text-v1 "
                         "hash would be wrong");
    }
    const std::string* content = string_at(body, "content");
    if (content == nullptr) {
        throw GraphError("Graph's reply listing " + location +
                         " has a message without body.content");
    }
    return text_v1_sha256(*content);
}

} // namespace

std::vector<FoundItem> TargetReader::list_mail()
{
    // The guard's mailbox check first, as the file targets run theirs (W3.2).
    check_restore_mailbox(graph_, targets_);
    const std::string& mailbox = targets_.mailbox();
    const std::string location = "the test mailbox's Inbox";
    const HttpHeaders prefer{{"Prefer", std::string{kMailPrefer}}};
    const std::vector<json> pages =
        list_pages(graph_,
                   "/users/" + mailbox + "/mailFolders/inbox/messages" +
                       std::string{kMailSelect} +
                       (options_.hash_items ? ",body" : "") + "&$top=100",
                   kMailReadGrant, prefer, location, [&mailbox](const std::vector<std::string>& path) {
                       return is_inbox_path(path, mailbox);
                   });
    std::vector<FoundItem> items;
    for (const json& page : pages) {
        for (const json& message : page.at("value")) {
            FoundItem item;
            item.type = ItemType::mail;
            item.id = graph_id(message, "a message in " + location);
            if (options_.hash_items) {
                item.sha256 = mail_body_sha256(message, location);
                item.sha256_rule = std::string{kTextV1};
            }
            item.subject = optional_string(message, "subject");
            const auto from = message.find("from");
            if (from != message.end() && from->is_object()) {
                const auto address = from->find("emailAddress");
                if (address != from->end()) {
                    item.sender = optional_string(*address, "address");
                    item.sender_name = optional_string(*address, "name");
                }
            }
            item.sent_at = optional_string(message, "sentDateTime");
            item.received_at = optional_string(message, "receivedDateTime");
            item.created_at = optional_string(message, "createdDateTime");
            item.internet_message_id = optional_string(message, "internetMessageId");
            items.push_back(std::move(item));
        }
    }
    log(spdlog::level::info,
        "listed " + std::to_string(items.size()) + " item(s) in " + location);
    return items;
}

std::vector<FoundItem> TargetReader::list_all()
{
    std::vector<FoundItem> items = list_mail();
    const auto append = [&items](std::vector<FoundItem> more) {
        items.insert(items.end(), std::make_move_iterator(more.begin()),
                     std::make_move_iterator(more.end()));
    };
    append(list_sharepoint());
    append(list_onedrive());
    return items;
}

std::vector<FoundItem> TargetReader::list_sharepoint()
{
    check_restore_library(graph_, targets_);
    const std::string& drive = targets_.library_id();
    return list_files({ItemType::sharepoint, &kSitesReadGrant, drive,
                       "/drives/" + drive + "/root/children" + std::string{kChildrenQuery},
                       "the RestoreTarget library",
                       [&drive](const std::vector<std::string>& path) {
                           return is_library_root_path(path, drive);
                       }});
}

std::vector<FoundItem> TargetReader::list_onedrive()
{
    check_restore_onedrive_folder(graph_, targets_);
    const std::string& drive = targets_.onedrive_drive_id();
    const std::string& folder = targets_.onedrive_folder_id();
    return list_files({ItemType::onedrive, &kOneDriveReadGrant, drive,
                       "/drives/" + drive + "/items/" + folder + "/children" +
                           std::string{kChildrenQuery},
                       "the test OneDrive folder",
                       [&drive, &folder](const std::vector<std::string>& path) {
                           return is_folder_path(path, drive, folder);
                       }});
}

} // namespace rp::graph
