#include <rp/graph_targets.hpp>

#include <rp/config.hpp>
#include <rp/redact.hpp>

#include "text_util.hpp"
#include "uuid.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <set>
#include <utility>

namespace rp::graph {

namespace {

using nlohmann::json;

constexpr std::string_view kSharePointSuffix = ".sharepoint.com";
constexpr std::string_view kChildrenQuery = "?$select=id,name,size,file,folder&$top=200";

std::string lower(std::string_view text)
{
    std::string out{text};
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool iequals(std::string_view a, std::string_view b)
{
    return lower(a) == lower(b);
}

// 1..max_size of ASCII letters, digits and the characters in `extra`.
bool is_id(std::string_view text, std::string_view extra, std::size_t max_size)
{
    return !text.empty() && text.size() <= max_size &&
           std::all_of(text.begin(), text.end(), [extra](char c) {
               const auto byte = static_cast<unsigned char>(c);
               return byte < 0x80 && (std::isalnum(byte) || extra.find(c) != std::string_view::npos);
           });
}

bool is_drive_id(std::string_view id)
{
    return id.starts_with("b!") && is_id(id.substr(2), "-_", 200);
}

bool is_item_id(std::string_view id)
{
    return is_id(id, "!-_", 200);
}

struct SiteId {
    std::string host; // lower case
    std::string site;
    std::string web;
};

// "<tenant>.sharepoint.com,<site GUID>,<web GUID>", the tenant one DNS label.
std::optional<SiteId> parse_site_id(std::string_view id)
{
    const std::size_t first = id.find(',');
    const std::size_t second = first == std::string_view::npos ? first : id.find(',', first + 1);
    if (second == std::string_view::npos) {
        return std::nullopt;
    }
    const std::string host = lower(id.substr(0, first));
    const std::string_view site = id.substr(first + 1, second - first - 1);
    const std::string_view web = id.substr(second + 1);
    if (!host.ends_with(kSharePointSuffix) || !is_uuid(site) || !is_uuid(web)) {
        return std::nullopt;
    }
    const std::string_view label =
        std::string_view{host}.substr(0, host.size() - kSharePointSuffix.size());
    if (!is_id(label, "-", 63)) {
        return std::nullopt;
    }
    return SiteId{host, std::string{site}, std::string{web}};
}

std::string percent_decode(std::string_view text)
{
    const auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        const char l = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return l >= 'a' && l <= 'f' ? l - 'a' + 10 : -1;
    };
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '%' && i + 2 < text.size() && hex(text[i + 1]) >= 0 &&
            hex(text[i + 2]) >= 0) {
            out += static_cast<char>(hex(text[i + 1]) * 16 + hex(text[i + 2]));
            i += 2;
        } else {
            out += text[i];
        }
    }
    return out;
}

// The resource a listing URL names, to compare a nextLink with the first
// request: the path after Graph's v1.0 root (the whole text if relative), up
// to the query, percent-decoded, "seg('v')" and "seg(v)" as "seg/v", lower case.
std::string resource_path(std::string_view url)
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
    return lower(out);
}

// Every page of a listing that starts at `first`, following @odata.nextLink.
std::vector<json> list_pages(GraphClient& graph, const std::string& first, const Grant& grant,
                             const HttpHeaders& headers, const std::string& what)
{
    const std::string first_url = std::string{kGraphBaseUrl} + first;
    const std::string first_resource = resource_path(first_url);
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
        if (next.empty() || fetched.contains(next) ||
            (next.starts_with(prefix) && resource_path(next) != first_resource)) {
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

// The string at `key` of the object `object`, if both are what they should be.
const std::string* string_at(const json& object, std::string_view key)
{
    if (!object.is_object()) {
        return nullptr;
    }
    const auto it = object.find(key);
    return it != object.end() && it->is_string() ? it->get_ptr<const std::string*>() : nullptr;
}

std::string quoted_name(const json& object)
{
    const std::string* name = string_at(object, "name");
    return "\"" + (name ? one_line(*name, 80) : std::string{"(none)"}) + "\"";
}

// The last segment of a URL's path, percent-decoded ("" when it has none).
std::string last_segment(std::string_view url)
{
    url = url.substr(0, std::min(url.find('?'), url.find('#')));
    if (url.ends_with('/')) {
        url.remove_suffix(1);
    }
    return percent_decode(url.substr(url.rfind('/') + 1));
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
    const std::optional<SiteId> site = parse_site_id(targets_.site_id());
    if (!site) {
        throw ConfigError("test_site_id", "test_site_id is not a Graph site ID "
                                          "(\"<tenant>.sharepoint.com,<site GUID>,<web GUID>\")");
    }
    const std::string drive_rule = "is not a Graph drive ID (\"b!\" then letters, digits, '-' "
                                   "and '_')";
    if (!is_drive_id(targets_.library_id())) {
        throw ConfigError("test_library_id", "test_library_id " + drive_rule);
    }
    if (!is_drive_id(targets_.onedrive_drive_id())) {
        throw ConfigError("test_onedrive_drive_id", "test_onedrive_drive_id " + drive_rule);
    }
    if (!is_item_id(targets_.onedrive_folder_id())) {
        throw ConfigError("test_onedrive_folder_id",
                          "test_onedrive_folder_id is not a Graph item ID (letters, digits, '!', "
                          "'-' and '_')");
    }
    tenant_host_ = site->host;
    site_guid_ = site->site;
    web_guid_ = site->web;
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

void TargetReader::check_library()
{
    const json drive = graph_.get_json("/drives/" + targets_.library_id() +
                                           "?$select=id,name,driveType,webUrl,sharePointIds",
                                       kSitesReadGrant);
    const std::string refused = ": the Worker reads only the RestoreTarget library; nothing was listed";
    const std::string* name = string_at(drive, "name");
    if (name == nullptr || *name != kRestoreTargetName) {
        throw WrongTargetError("the drive test_library_id names is " + quoted_name(drive) +
                               ", not \"RestoreTarget\"" + refused);
    }
    const std::string* web_url = string_at(drive, "webUrl");
    if (web_url == nullptr || !iequals(last_segment(*web_url), kRestoreTargetName)) {
        throw WrongTargetError("the drive test_library_id names has the address of another "
                               "library (not .../RestoreTarget)" + refused);
    }
    const std::string* drive_type = string_at(drive, "driveType");
    if (drive_type == nullptr || *drive_type != "documentLibrary") {
        throw WrongTargetError(
            "the drive test_library_id names is not a document library; nothing was listed");
    }
    const auto ids = drive.find("sharePointIds");
    const std::string* site = ids == drive.end() ? nullptr : string_at(*ids, "siteId");
    const std::string* web = ids == drive.end() ? nullptr : string_at(*ids, "webId");
    if (site == nullptr || web == nullptr) {
        throw WrongTargetError("Graph's reply for the drive test_library_id names has no "
                               "sharePointIds; the Worker can't check it is in the test site; "
                               "nothing was listed");
    }
    if (!iequals(*site, site_guid_) || !iequals(*web, web_guid_)) {
        throw WrongTargetError("the drive test_library_id names is not in the site test_site_id "
                               "names; nothing was listed");
    }
}

void TargetReader::check_onedrive_folder()
{
    const std::string& drive_id = targets_.onedrive_drive_id();
    json folder;
    try {
        folder = graph_.get_json("/drives/" + drive_id + "/items/" +
                                     targets_.onedrive_folder_id() +
                                     "?$select=id,name,folder,parentReference",
                                 kOneDriveReadGrant);
    } catch (const NotFoundError& e) {
        // SharePoint answers 404, not 403, for an item the app may not read.
        throw NotFoundError(std::string{e.what()} +
                                "; if the folder test_onedrive_folder_id names does exist, the "
                                "Worker app may lack the grant \"" +
                                std::string{kOneDriveReadGrant.description} +
                                "\" (SharePoint answers 404 for an item the app may not read)",
                            e.status(), e.code(), e.inner_code(), e.request_id());
    }
    const std::string* name = string_at(folder, "name");
    if (name == nullptr || *name != kRestoreTargetName) {
        throw WrongTargetError("the OneDrive item test_onedrive_folder_id names is " +
                               quoted_name(folder) +
                               ", not \"RestoreTarget\": the Worker reads only the RestoreTarget "
                               "folder; nothing was listed");
    }
    const auto facet = folder.find("folder");
    if (facet == folder.end() || !facet->is_object()) {
        throw WrongTargetError("the OneDrive item test_onedrive_folder_id names is not a folder; "
                               "nothing was listed");
    }
    const auto parent = folder.find("parentReference");
    const json none;
    const json& reference = parent == folder.end() ? none : *parent;
    const std::string* parent_drive = string_at(reference, "driveId");
    if (parent_drive == nullptr || *parent_drive != drive_id) {
        throw WrongTargetError("the OneDrive folder test_onedrive_folder_id names is not in the "
                               "drive test_onedrive_drive_id names; nothing was listed");
    }
    const std::string* path = string_at(reference, "path");
    if (path == nullptr) {
        throw WrongTargetError("Graph's reply for the OneDrive folder test_onedrive_folder_id "
                               "names has no parentReference.path; the Worker can't check it is "
                               "at the drive's root; nothing was listed");
    }
    // Graph writes the root either way (the recorded reply has the second).
    if (*path != "/drive/root:" && *path != "/drives/" + drive_id + "/root:") {
        throw WrongTargetError("the OneDrive folder test_onedrive_folder_id names is not directly "
                               "under the drive's root; nothing was listed");
    }
}

std::vector<FoundItem> TargetReader::list_files(const FileTarget& target)
{
    const std::vector<json> pages =
        list_pages(graph_, target.children_path, *target.grant, {}, target.location);
    std::vector<FoundItem> items;
    log(spdlog::level::info,
        "listed " + std::to_string(items.size()) + " item(s) in " + target.location);
    return items;
}

std::vector<FoundItem> TargetReader::list_sharepoint()
{
    check_library();
    const std::string& drive = targets_.library_id();
    return list_files({ItemType::sharepoint, &kSitesReadGrant, drive,
                       "/drives/" + drive + "/root/children" + std::string{kChildrenQuery},
                       "the RestoreTarget library"});
}

std::vector<FoundItem> TargetReader::list_onedrive()
{
    check_onedrive_folder();
    const std::string& drive = targets_.onedrive_drive_id();
    return list_files({ItemType::onedrive, &kOneDriveReadGrant, drive,
                       "/drives/" + drive + "/items/" + targets_.onedrive_folder_id() +
                           "/children" + std::string{kChildrenQuery},
                       "the test OneDrive folder"});
}

} // namespace rp::graph
