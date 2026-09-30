#include <rp/canary_manifest.hpp>

#include <rp/config.hpp>
#include <rp/sha256.hpp>

#include "folder_path.hpp"
#include "name_key.hpp"
#include "path_utf8.hpp"
#include "text_util.hpp"
#include "uuid.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <initializer_list>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace rp::sampling {

namespace {

using nlohmann::json;

constexpr std::string_view kSchema = "seed-manifest.v1";
constexpr std::string_view kNonEmpty = "must be a non-empty string";

[[noreturn]] void refuse(const std::string& pointer, std::string_view rule)
{
    throw ManifestError("canary manifest: " + pointer + ": " + std::string{rule});
}

// The string at `object[key]`, else a refusal naming `pointer/key`.
const std::string& text_at(const json& object, std::string_view key, const std::string& pointer)
{
    const auto it = object.find(std::string{key});
    if (it == object.end() || !it->is_string() || it->get_ref<const std::string&>().empty()) {
        refuse(pointer + "/" + std::string{key}, kNonEmpty);
    }
    return it->get_ref<const std::string&>();
}

// `value` when it is one of `allowed`, else a refusal with `rule`.
std::string one_of(const json& object, std::string_view key, const std::string& pointer,
                   std::initializer_list<std::string_view> allowed, std::string_view rule)
{
    const auto it = object.find(std::string{key});
    if (it != object.end() && it->is_string()) {
        const std::string& value = it->get_ref<const std::string&>();
        if (std::find(allowed.begin(), allowed.end(), value) != allowed.end()) {
            return value;
        }
    }
    refuse(pointer + "/" + std::string{key}, rule);
}

const json& location_of(const json& entry, const std::string& pointer)
{
    const auto it = entry.find("location");
    if (it == entry.end() || !it->is_object()) {
        refuse(pointer + "/location", "must be an object");
    }
    return *it;
}

// "YYYY-MM-DDTHH:MM:SSZ": digits where the digits are, nothing else, and a
// real date (leap years counted) and time (no leap second: Graph writes none).
bool is_whole_second_utc(std::string_view value)
{
    constexpr std::string_view shape = "dddd-dd-ddTdd:dd:ddZ";
    if (value.size() != shape.size()) {
        return false;
    }
    for (std::size_t i = 0; i < shape.size(); ++i) {
        if (shape[i] == 'd' ? value[i] < '0' || value[i] > '9' : value[i] != shape[i]) {
            return false;
        }
    }
    const auto number = [&](std::size_t at, std::size_t digits) {
        int out = 0;
        for (std::size_t i = at; i < at + digits; ++i) {
            out = out * 10 + (value[i] - '0');
        }
        return out;
    };
    const std::chrono::year_month_day date{std::chrono::year{number(0, 4)},
                                           std::chrono::month{static_cast<unsigned>(number(5, 2))},
                                           std::chrono::day{static_cast<unsigned>(number(8, 2))}};
    return date.ok() && number(11, 2) < 24 && number(14, 2) < 60 && number(17, 2) < 60;
}

// Starts with "/" and has no ".." segment (folder_path.hpp, the guard's rule).
bool is_manifest_folder_path(std::string_view path)
{
    return path.starts_with('/') && !has_dot_dot_segment(path);
}

// The first entry of each folded name or subject, per kind, so a repeat
// names it. A subject is folded A-Z only; a file name by name_key, as
// SharePoint and OneDrive compare names and restore_sample refuses two of one
// name (W2.6 review), so a manifest the rotation would one day turn into a
// refused run is refused here, when it loads.
class Seen {
public:
    using Fold = std::string (*)(std::string_view);

    explicit Seen(Fold fold) : fold_(fold) {}

    void add(const std::string& value, const std::string& pointer, std::string_view field)
    {
        const auto [it, added] = first_.emplace(fold_(value), pointer);
        if (!added) {
            refuse(pointer + "/" + std::string{field},
                   "repeats " + it->second + "/" + std::string{field} + " (ignoring case)");
        }
    }

private:
    Fold fold_;
    std::map<std::string, std::string> first_;
};

CanaryMail read_mail(const json& entry, const std::string& pointer)
{
    CanaryMail mail;
    mail.subject = text_at(entry, "subject", pointer);
    const auto received = entry.find("received_at");
    if (received == entry.end() || !received->is_string() ||
        !is_whole_second_utc(received->get_ref<const std::string&>())) {
        refuse(pointer + "/received_at",
               "must be \"YYYY-MM-DDTHH:MM:SSZ\", a real date and time in UTC");
    }
    mail.received_at = received->get<std::string>();
    const json& location = location_of(entry, pointer);
    mail.mailbox = text_at(location, "mailbox", pointer + "/location");
    // The target guard's rule: no address holds either.
    if (std::ranges::any_of(mail.mailbox, [](char c) {
            return static_cast<unsigned char>(c) <= 0x20 || c == 0x7F;
        })) {
        refuse(pointer + "/location/mailbox", "holds whitespace or a control character");
    }
    if (is_restore_mailbox(mail.mailbox)) {
        refuse(pointer + "/location/mailbox", "is a restore target (a restoretest mailbox)");
    }
    mail.folder = text_at(location, "folder", pointer + "/location");
    return mail;
}

CanaryFile read_file(const json& entry, const std::string& pointer, bool sharepoint)
{
    CanaryFile file;
    file.name = text_at(entry, "name", pointer);
    file.file_type = one_of(entry, "file_type", pointer, {"pdf", "docx", "xlsx", "txt", "png"},
                            "must be \"pdf\", \"docx\", \"xlsx\", \"txt\" or \"png\"");
    file.content_rule = one_of(entry, "content_rule", pointer, {"bytes", "office-v1"},
                               "must be \"bytes\" or \"office-v1\"") == "bytes"
                            ? ContentRule::bytes
                            : ContentRule::office_v1;
    const auto size = entry.find("stored_size");
    if (size == entry.end() || !size->is_number_integer() || size->get<std::int64_t>() < 0) {
        refuse(pointer + "/stored_size", "must be an integer of 0 or more");
    }
    file.stored_size = size->get<std::int64_t>();
    const json& location = location_of(entry, pointer);
    const std::string where = pointer + "/location";
    const auto folder_path = location.find("folder_path");
    if (folder_path == location.end() || !folder_path->is_string() ||
        !is_manifest_folder_path(folder_path->get_ref<const std::string&>())) {
        refuse(where + "/folder_path", "must start with \"/\" and have no \"..\" segment, backslash or colon");
    }
    file.folder_path = folder_path->get<std::string>();
    if (sharepoint) {
        const auto string_or_empty = [&](std::string_view key) {
            const auto it = location.find(std::string{key});
            return it != location.end() && it->is_string() ? it->get<std::string>() : std::string{};
        };
        file.site_id = string_or_empty("site_id");
        if (!parse_graph_site_id(file.site_id)) {
            refuse(where + "/site_id", kGraphSiteIdRule);
        }
        file.drive_id = string_or_empty("drive_id");
        if (!is_graph_drive_id(file.drive_id)) {
            refuse(where + "/drive_id", kGraphDriveIdRule);
        }
        file.list_id = string_or_empty("list_id");
        if (!is_uuid(file.list_id)) {
            refuse(where + "/list_id", "must be a GUID");
        }
    } else {
        file.user = text_at(location, "user", where);
    }
    return file;
}

} // namespace

CanaryManifest parse_canary_manifest(std::string_view json_text)
{
    json root;
    try {
        root = json::parse(json_text);
    } catch (const json::parse_error&) {
        throw ManifestError("canary manifest: isn't valid JSON");
    } catch (const json::exception&) {
        // out_of_range 406: a number too large for a double. Its message
        // quotes the number, so it is never passed on (as parse_config).
        throw ManifestError("canary manifest: isn't valid JSON (a number is out of range)");
    }
    if (!root.is_object()) {
        throw ManifestError("canary manifest: must be a JSON object");
    }
    const auto schema = root.find("schema");
    if (schema == root.end() || !schema->is_string() || schema->get_ref<const std::string&>() != kSchema) {
        refuse("/schema", "must be \"seed-manifest.v1\"");
    }
    const auto tenant = root.find("tenant_id");
    if (tenant == root.end() || !tenant->is_string() ||
        !is_uuid(tenant->get_ref<const std::string&>())) {
        refuse("/tenant_id", "must be a GUID");
    }
    const auto entries = root.find("entries");
    if (entries == root.end() || !entries->is_array()) {
        refuse("/entries", "must be an array");
    }

    CanaryManifest manifest;
    manifest.tenant_id = tenant->get<std::string>();
    manifest.sha256 = sha256_hex(json_text);
    std::map<std::string, std::string> ids;
    Seen subjects{ascii_lower};
    Seen sharepoint_names{name_key};
    Seen onedrive_names{name_key};
    for (std::size_t i = 0; i < entries->size(); ++i) {
        const json& entry = entries->at(i);
        const std::string pointer = "/entries/" + std::to_string(i);
        if (!entry.is_object()) {
            refuse(pointer, "must be an object");
        }
        const std::string kind =
            one_of(entry, "kind", pointer, {"mail", "sharepoint_file", "onedrive_file"},
                   "must be \"mail\", \"sharepoint_file\" or \"onedrive_file\"");
        const std::string& id = text_at(entry, "id", pointer);
        if (const auto [it, added] = ids.emplace(id, pointer); !added) {
            refuse(pointer + "/id", "repeats " + it->second + "/id");
        }
        if (kind == "mail") {
            CanaryMail mail = read_mail(entry, pointer);
            subjects.add(mail.subject, pointer, "subject");
            mail.entry = i;
            mail.id = id;
            manifest.mail.push_back(std::move(mail));
        } else {
            const bool sharepoint = kind == "sharepoint_file";
            CanaryFile file = read_file(entry, pointer, sharepoint);
            (sharepoint ? sharepoint_names : onedrive_names).add(file.name, pointer, "name");
            file.entry = i;
            file.id = id;
            (sharepoint ? manifest.sharepoint : manifest.onedrive).push_back(std::move(file));
        }
    }
    return manifest;
}

CanaryManifest load_canary_manifest(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw ManifestError("canary manifest: " + path_to_utf8(path) + ": cannot read the file");
    }
    std::ostringstream text;
    text << file.rdbuf();
    return parse_canary_manifest(text.str());
}

connector::MailSelector to_selector(const CanaryMail& canary)
{
    return {canary.mailbox, canary.folder, canary.subject, canary.received_at};
}

namespace {

std::int64_t selector_size(const CanaryFile& canary)
{
    return canary.content_rule == ContentRule::bytes ? canary.stored_size : -1;
}

} // namespace

connector::SharePointSelector to_sharepoint_selector(const CanaryFile& canary)
{
    return {canary.site_id,     canary.drive_id, canary.folder_path,
            canary.name,        canary.list_id,  selector_size(canary)};
}

connector::OneDriveSelector to_onedrive_selector(const CanaryFile& canary)
{
    return {canary.user, canary.folder_path, canary.name, selector_size(canary)};
}

} // namespace rp::sampling
