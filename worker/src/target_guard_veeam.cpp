#include <rp/target_guard_veeam.hpp>

#include <rp/config.hpp>

#include "target_guard_refuse.hpp"
#include "text_util.hpp"
#include "uuid.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp::veeam {

namespace {

using nlohmann::json;

constexpr std::string_view kPathPrefix = "/v8/RestoreSessions/";
constexpr std::size_t kGuidSize = 36;

// Names no target may take, whatever layer 1 resolved (restore-flow §6). Not
// what keeps a live library out: that is layer 1's exact name.
constexpr std::array<std::string_view, 3> kForbiddenNames = {"RestoreTest", "Documents",
                                                             "Shared Documents"};

// One kind of restore call: its path and its body's exact key set.
struct KindRules {
    std::string_view name;       // as in messages
    std::string_view container;  // the path between the explore session and the container
    std::string_view action;     // the path after the container
    std::set<std::string> keys;  // the body's keys (restore-flow §5)
};

const KindRules kMail{"mail",
                      "/organization/mailboxes/",
                      "/items/restoreTo",
                      {"mailbox", "folder", "items", "changedItems", "deletedItems",
                       "markRestoredAsUnread", "excludeDrafts", "excludeDeletedItems",
                       "excludeInPlaceHoldItems", "excludeLitigationHoldItems", "officeRegion",
                       "officeOrganizationName", "applicationId", "applicationCertificate",
                       "applicationCertificatePassword", "impersonationAccountName"}};
const KindRules kSharePoint{"sharepoint",
                            "/Organization/Sites/",
                            "/Documents/restoreTo",
                            {"documents", "siteURL", "list", "sendSharedLinksNotification",
                             "documentVersion", "documentLastVersionAction", "officeRegion",
                             "organizationName", "applicationId", "applicationCertificate",
                             "applicationCertificatePassword"}};
const KindRules kOneDrive{"onedrive",
                          "/Organization/OneDrives/",
                          "/Documents/copyTo",
                          {"documents", "onedrive", "folder", "changedItems", "deletedItems",
                           "documentVersion", "documentLastVersionAction", "officeRegion",
                           "organizationName", "applicationId", "applicationCertificate",
                           "applicationCertificatePassword"}};

// A kind outside the enum is taken as OneDrive's: every rule still applies.
const KindRules& rules_for(RestoreKind kind)
{
    switch (kind) {
    case RestoreKind::mail:
        return kMail;
    case RestoreKind::sharepoint:
        return kSharePoint;
    case RestoreKind::onedrive:
        break;
    }
    return kOneDrive;
}

bool is_printable_ascii(std::string_view text)
{
    return std::all_of(text.begin(), text.end(), [](char c) { return c >= 0x20 && c <= 0x7E; });
}

bool is_lower_guid(std::string_view text)
{
    return is_uuid(text) && ascii_lower(text) == text;
}

// One or more lower-case GUIDs run together, as Veeam writes a container ID.
bool is_guids(std::string_view text)
{
    if (text.empty() || text.size() % kGuidSize != 0) {
        return false;
    }
    for (std::size_t at = 0; at < text.size(); at += kGuidSize) {
        if (!is_lower_guid(text.substr(at, kGuidSize))) {
            return false;
        }
    }
    return true;
}

std::string joined(const std::vector<std::string>& names)
{
    if (names.empty()) {
        return "none";
    }
    std::string out;
    for (const std::string& name : names) {
        out += (out.empty() ? "" : ", ") + name;
    }
    return one_line(out, 200);
}

// Reads the body for the checks, refusing through the guard: every refusal's
// message names a field, never quotes a credential.
class Reader {
public:
    explicit Reader(const TargetGuardOptions& options) : options_(options) {}

    [[noreturn]] void refuse(const std::string& why) const
    {
        refuse_restore(options_, "target guard: " + why + "; the restore was not sent");
    }

    const json& member(const json& object, const std::string& key, const std::string& what) const
    {
        const auto it = object.find(key);
        if (it == object.end()) {
            refuse(what + " is missing");
        }
        return *it;
    }

    const std::string& string(const json& value, const std::string& what) const
    {
        if (!value.is_string()) {
            refuse(what + " is not a JSON string");
        }
        return value.get_ref<const std::string&>();
    }

    // A value compared with a target or fixed name.
    const std::string& ascii(const json& value, const std::string& what) const
    {
        const std::string& text = string(value, what);
        if (!is_printable_ascii(text)) {
            refuse(what + " has a character outside printable ASCII");
        }
        return text;
    }

    bool boolean(const json& value, const std::string& what) const
    {
        if (!value.is_boolean()) {
            refuse(what + " is not a JSON boolean");
        }
        return value.get<bool>();
    }

    const json& array(const json& value, const std::string& what) const
    {
        if (!value.is_array()) {
            refuse(what + " is not a JSON array");
        }
        return value;
    }

    // The exact text as JSON: an object at the top, and no object at any depth
    // with a key twice (nlohmann keeps the last one silently).
    json parse(std::string_view body) const
    {
        std::vector<std::set<std::string>> open;
        bool twice = false;
        json doc;
        try {
            doc = json::parse(body.begin(), body.end(),
                              [&](int, json::parse_event_t event, json& parsed) {
                                  if (event == json::parse_event_t::object_start) {
                                      open.emplace_back();
                                  } else if (event == json::parse_event_t::key) {
                                      twice |= !open.back().insert(parsed.get<std::string>()).second;
                                  } else if (event == json::parse_event_t::object_end) {
                                      open.pop_back();
                                  }
                                  return true;
                              });
        } catch (const json::exception&) {
            // Its message quotes the text around the error: never passed on.
            refuse("the body is not valid JSON");
        }
        if (twice) {
            refuse("the body has a key twice in one object");
        }
        if (!doc.is_object()) {
            refuse("the body is not a JSON object");
        }
        return doc;
    }

private:
    const TargetGuardOptions& options_;
};

void check_context(const Reader& reader, const CheckedTargets& targets,
                   const RestoreRequestContext& ctx)
{
    if (ctx.items.empty()) {
        reader.refuse("bad context: no items to restore");
    }
    std::set<std::string> ids;
    for (const GuardedItem& item : ctx.items) {
        if (!ids.insert(item.id).second) {
            reader.refuse("bad context: an item ID appears twice");
        }
    }
    if (!is_guids(ctx.container_id)) {
        reader.refuse("bad context: the container ID is not one or more lower-case GUIDs");
    }
    if (ctx.kind == RestoreKind::sharepoint && !targets.library()) {
        reader.refuse("bad context: the RestoreTarget library was not checked (the spec had no "
                      "SharePoint item)");
    }
    std::vector<std::pair<std::string_view, const std::string*>> values = {
        {"application_id", &ctx.application_id},
        {"organization_name", &ctx.organization_name},
        {"office_region", &ctx.office_region}};
    // OneDrive's, and a kind outside the enum's (rules_for).
    if (ctx.kind != RestoreKind::mail && ctx.kind != RestoreKind::sharepoint) {
        if (!targets.onedrive_folder()) {
            reader.refuse("bad context: the RestoreTarget folder was not checked (the spec had "
                          "no OneDrive item)");
        }
        values.emplace_back("target_onedrive_id", &ctx.target_onedrive_id);
        values.emplace_back("target_onedrive_url", &ctx.target_onedrive_url);
    }
    for (const auto& [name, value] : values) {
        if (value->empty() || !is_printable_ascii(*value)) {
            reader.refuse("bad context: " + std::string{name} +
                          " is empty or not printable ASCII");
        }
    }
}

void check_path(const Reader& reader, const RestoreRequestContext& ctx, const KindRules& rules,
                std::string_view path)
{
    // Refused for what they are before the exact comparison below, which would
    // refuse them too.
    const bool odd = std::ranges::any_of(
                         std::array<std::string_view, 7>{"?", "#", "%", "\\", "//", "/./", "/../"},
                         [path](std::string_view bad) {
                             return path.find(bad) != std::string_view::npos;
                         }) ||
                     path.ends_with("/.") || path.ends_with("/..");
    if (odd) {
        reader.refuse("the path has a query, fragment, escape or dot segment");
    }
    const std::string_view explore = path.starts_with(kPathPrefix)
                                         ? path.substr(kPathPrefix.size(), kGuidSize)
                                         : std::string_view{};
    const auto& opened = ctx.opened_explore_sessions;
    if (!is_lower_guid(explore) ||
        std::find(opened.begin(), opened.end(), std::string{explore}) == opened.end()) {
        reader.refuse("the explore session in the path is not one this run opened");
    }
    const std::string expected = std::string{kPathPrefix} + std::string{explore} +
                                 std::string{rules.container} + ctx.container_id +
                                 std::string{rules.action};
    if (path != expected) {
        reader.refuse("the path is not the " + std::string{rules.name} +
                      " restore-to-another-location call");
    }
}

void check_keys(const Reader& reader, const KindRules& rules, const json& body)
{
    std::set<std::string> keys;
    for (const auto& [key, value] : body.items()) {
        keys.insert(key);
    }
    if (keys != rules.keys) {
        std::vector<std::string> extra;
        std::vector<std::string> missing;
        std::ranges::set_difference(keys, rules.keys, std::back_inserter(extra));
        std::ranges::set_difference(rules.keys, keys, std::back_inserter(missing));
        reader.refuse("the " + std::string{rules.name} +
                      " body's keys are not exactly the expected set (extra: " + joined(extra) +
                      "; missing: " + joined(missing) + ")");
    }
}

using Items = std::vector<std::pair<std::string, std::string>>; // (id, name)

// The checks of one request's body, in the order they run.
class RequestCheck {
public:
    RequestCheck(const Reader& reader, const CheckedTargets& targets,
                 const RestoreRequestContext& ctx, const json& body)
        : reader_(reader), targets_(targets), ctx_(ctx), body_(body)
    {
    }

    // officeRegion, applicationId and the two credential fields.
    void common() const
    {
        if (ascii("officeRegion") != ctx_.office_region) {
            reader_.refuse("officeRegion is not the organisation's region");
        }
        if (ascii("applicationId") != ctx_.application_id) {
            reader_.refuse("applicationId is not the organisation's app");
        }
        // Kinds only: a credential's value is never compared, quoted or logged.
        reader_.string(body_.at("applicationCertificate"), "applicationCertificate");
        reader_.string(body_.at("applicationCertificatePassword"),
                       "applicationCertificatePassword");
    }

    Items mail() const
    {
        const std::string& mailbox = targets_.mailbox();
        if (ascii("mailbox") != mailbox) {
            reader_.refuse("mailbox is not the test mailbox");
        }
        if (ascii("impersonationAccountName") != mailbox) {
            reader_.refuse("impersonationAccountName is not the test mailbox");
        }
        if (ascii("folder") != "Inbox") {
            reader_.refuse("folder is not Inbox");
        }
        if (ascii("officeOrganizationName") != ctx_.organization_name) {
            reader_.refuse("officeOrganizationName is not the organisation's");
        }
        for (const char* flag : {"changedItems", "deletedItems", "markRestoredAsUnread",
                                 "excludeDrafts", "excludeDeletedItems", "excludeInPlaceHoldItems",
                                 "excludeLitigationHoldItems"}) {
            reader_.boolean(body_.at(flag), flag);
        }
        Items items;
        const json& list = reader_.array(body_.at("items"), "items");
        for (std::size_t i = 0; i < list.size(); ++i) {
            const std::string what = "items[" + std::to_string(i) + "]";
            const json& item = list[i];
            if (!item.is_object() || item.size() != 1 || !item.contains("id")) {
                reader_.refuse(what + " is not an object holding only an id");
            }
            items.emplace_back(reader_.string(item.at("id"), what + ".id"), "");
        }
        return items;
    }

    Items sharepoint() const
    {
        const graph::ResolvedLibrary& library = *targets_.library();
        if (ascii("siteURL") != library.site_url) {
            reader_.refuse("siteURL is not the RestoreTarget library's site");
        }
        const std::string& list = ascii("list");
        if (list != library.name || is_forbidden(list)) {
            reader_.refuse("list is not the RestoreTarget library");
        }
        file_options();
        if (reader_.boolean(body_.at("sendSharedLinksNotification"),
                            "sendSharedLinksNotification")) {
            reader_.refuse("sendSharedLinksNotification is not false");
        }
        // Veeam's document IDs are the site, web and list GUIDs, then the item's.
        const std::string target_list =
            ascii_lower(library.site_id + library.web_id + library.list_id);
        return documents("siteId", "site", [&](const std::string& what, const std::string& id) {
            if (!id.starts_with(ctx_.container_id)) {
                reader_.refuse(what + ".id is not in the site in the path");
            }
            if (ascii_lower(id).starts_with(target_list)) {
                reader_.refuse(what + " is sampled from the RestoreTarget library: a restore "
                                      "target is never a source");
            }
        });
    }

    Items onedrive() const
    {
        const graph::ResolvedOneDriveFolder& folder = *targets_.onedrive_folder();
        const json& target = body_.at("onedrive");
        if (!target.is_object() || target.size() != 3 || !target.contains("id") ||
            !target.contains("name") || !target.contains("url")) {
            reader_.refuse("onedrive is not an object of exactly id, name and url");
        }
        const std::string& id = reader_.ascii(target.at("id"), "onedrive.id");
        if (id != ctx_.target_onedrive_id ||
            !ascii_iequals(id.substr(0, kGuidSize), folder.site_id)) {
            reader_.refuse("onedrive.id is not the test OneDrive");
        }
        // The test OneDrive is on the tenant's -my host; test_site_id names the tenant.
        const std::string host = parse_graph_site_id(targets_.configured().site_id()).value().host;
        const std::string root = "https://" + host.substr(0, host.find('.')) + "-my" +
                                 std::string{kSharePointSuffix} + "/";
        const std::string& url = reader_.ascii(target.at("url"), "onedrive.url");
        if (url != ctx_.target_onedrive_url || !ascii_lower(url).starts_with(root) ||
            url.find_first_of("?#") != std::string::npos) {
            reader_.refuse("onedrive.url is not the test OneDrive's address");
        }
        if (reader_.string(target.at("name"), "onedrive.name") != ctx_.target_onedrive_name) {
            reader_.refuse("onedrive.name is not the test OneDrive's");
        }
        const std::string& name = ascii("folder");
        if (name != folder.name || is_forbidden(name)) {
            reader_.refuse("folder is not the RestoreTarget folder");
        }
        file_options();
        reader_.boolean(body_.at("changedItems"), "changedItems");
        reader_.boolean(body_.at("deletedItems"), "deletedItems");
        return documents("oneDriveId", "OneDrive", [](const std::string&, const std::string&) {});
    }

private:
    const std::string& ascii(const char* key) const { return reader_.ascii(body_.at(key), key); }

    static bool is_forbidden(std::string_view name)
    {
        return std::ranges::find(kForbiddenNames, name) != kForbiddenNames.end();
    }

    // organizationName and the version options, as both file bodies carry them.
    void file_options() const
    {
        if (ascii("organizationName") != ctx_.organization_name) {
            reader_.refuse("organizationName is not the organisation's");
        }
        if (ascii("documentVersion") != "Last") {
            reader_.refuse("documentVersion is not Last");
        }
        if (ascii("documentLastVersionAction") != "Merge") {
            reader_.refuse("documentLastVersionAction is not Merge");
        }
    }

    // Each document: an object with a string id and name whose `owner_key`
    // (siteId, oneDriveId) is the container in the path, not a folder; then
    // `check_id` on its ID.
    template <typename CheckId>
    Items documents(const std::string& owner_key, const std::string& owner,
                    const CheckId& check_id) const
    {
        Items items;
        const json& list = reader_.array(body_.at("documents"), "documents");
        for (std::size_t i = 0; i < list.size(); ++i) {
            const std::string what = "documents[" + std::to_string(i) + "]";
            const json& document = list[i];
            if (!document.is_object()) {
                reader_.refuse(what + " is not a JSON object");
            }
            const std::string& id = field(document, what, "id");
            const std::string& name = field(document, what, "name");
            const std::string owner_what = what + "." + owner_key;
            if (reader_.ascii(reader_.member(document, owner_key, owner_what), owner_what) !=
                ctx_.container_id) {
                reader_.refuse(owner_what + " is not the " + owner + " in the path");
            }
            const std::string folder_what = what + ".isFolder";
            if (reader_.boolean(reader_.member(document, "isFolder", folder_what), folder_what)) {
                reader_.refuse(what + " is a folder");
            }
            check_id(what, id);
            items.emplace_back(id, name);
        }
        return items;
    }

    // The string `key` of `document`.
    const std::string& field(const json& document, const std::string& what,
                             const std::string& key) const
    {
        const std::string field_what = what + "." + key;
        return reader_.string(reader_.member(document, key, field_what), field_what);
    }

    const Reader& reader_;
    const CheckedTargets& targets_;
    const RestoreRequestContext& ctx_;
    const json& body_;
};

} // namespace

void check_restore_request(const CheckedTargets& targets, const RestoreRequestContext& ctx,
                           std::string_view path, std::string_view body,
                           const TargetGuardOptions& options)
{
    const Reader reader(options);
    const KindRules& rules = rules_for(ctx.kind);
    check_context(reader, targets, ctx);
    check_path(reader, ctx, rules, path);
    const json doc = reader.parse(body);
    check_keys(reader, rules, doc);
    const RequestCheck check(reader, targets, ctx, doc);
    check.common();
    Items found = ctx.kind == RestoreKind::mail         ? check.mail()
                  : ctx.kind == RestoreKind::sharepoint ? check.sharepoint()
                                                        : check.onedrive();
    // Exactly the resolved set: none missing, none added, none twice.
    Items wanted;
    for (const GuardedItem& item : ctx.items) {
        wanted.emplace_back(item.id, item.name);
    }
    std::ranges::sort(found);
    std::ranges::sort(wanted);
    if (found != wanted) {
        reader.refuse("the body's items are not exactly the ones resolved");
    }
}

} // namespace rp::veeam
