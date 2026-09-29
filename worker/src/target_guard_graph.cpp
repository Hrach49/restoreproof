#include <rp/target_guard_graph.hpp>

#include <rp/config.hpp>

#include "json_fields.hpp"
#include "text_util.hpp"
#include "uuid.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <optional>

namespace rp::graph {

namespace {

using nlohmann::json;

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

ResolvedLibrary check_restore_library(GraphClient& graph, const connector::RestoreTargets& targets,
                                      const TargetCheckWording& wording)
{
    // RestoreTargets::from_config checked every ID's shape, the site ID's too.
    const GraphSiteId site_id = parse_graph_site_id(targets.site_id()).value();
    const json drive = graph.get_json("/drives/" + targets.library_id() +
                                          "?$select=id,name,driveType,webUrl,sharePointIds",
                                      kSitesReadGrant);
    const std::string outcome = "; " + std::string{wording.outcome};
    const std::string refused =
        ": the Worker " + std::string{wording.only} + " the RestoreTarget library" + outcome;
    const std::string* name = string_at(drive, "name");
    if (name == nullptr || *name != kRestoreTargetName) {
        throw WrongTargetError("the drive test_library_id names is " + quoted_name(drive) +
                               ", not \"RestoreTarget\"" + refused);
    }
    const std::string* web_url = string_at(drive, "webUrl");
    if (web_url == nullptr || !ascii_iequals(last_segment(*web_url), kRestoreTargetName)) {
        throw WrongTargetError("the drive test_library_id names has the address of another "
                               "library (not .../RestoreTarget)" + refused);
    }
    const std::string* drive_type = string_at(drive, "driveType");
    if (drive_type == nullptr || *drive_type != "documentLibrary") {
        throw WrongTargetError("the drive test_library_id names is not a document library" +
                               outcome);
    }
    const auto ids = drive.find("sharePointIds");
    const json none;
    const json& sharepoint_ids = ids == drive.end() ? none : *ids;
    const std::string* site = string_at(sharepoint_ids, "siteId");
    const std::string* web = string_at(sharepoint_ids, "webId");
    if (site == nullptr || web == nullptr) {
        throw WrongTargetError("Graph's reply for the drive test_library_id names has no "
                               "sharePointIds; the Worker can't check it is in the test site" +
                               outcome);
    }
    if (!ascii_iequals(*site, site_id.site) || !ascii_iequals(*web, site_id.web)) {
        throw WrongTargetError(
            "the drive test_library_id names is not in the site test_site_id names" + outcome);
    }
    // W2.7: a restore names the library by its site URL and list (restore-flow §16).
    const std::string* list_id = string_at(sharepoint_ids, "listId");
    const std::string* site_url = string_at(sharepoint_ids, "siteUrl");
    if (list_id == nullptr || !is_uuid(*list_id) || site_url == nullptr) {
        throw WrongTargetError("Graph's reply for the drive test_library_id names has no list ID "
                               "or site URL in sharePointIds; the Worker can't tell the library "
                               "apart" + outcome);
    }
    ResolvedLibrary library{*name, targets.library_id(), *list_id, *site, *web, *site_url};
    return library;
}

ResolvedOneDriveFolder check_restore_onedrive_folder(GraphClient& graph,
                                                     const connector::RestoreTargets& targets,
                                                     const TargetCheckWording& wording)
{
    const std::string& drive_id = targets.onedrive_drive_id();
    json folder;
    std::optional<NotFoundError> missing;
    try {
        folder = graph.get_json("/drives/" + drive_id + "/items/" + targets.onedrive_folder_id() +
                                    "?$select=id,name,folder,parentReference",
                                kOneDriveReadGrant);
    } catch (const NotFoundError& e) {
        // SharePoint answers 404, not 403, for an item the app may not read.
        missing.emplace(std::string{e.what()} +
                            "; if the folder test_onedrive_folder_id names does exist, the "
                            "Worker app may lack the grant \"" +
                            std::string{kOneDriveReadGrant.description} +
                            "\" (SharePoint answers 404 for an item the app may not read)",
                        e.status(), e.code(), e.inner_code(), e.request_id());
    }
    if (missing) {
        throw *missing;
    }
    const std::string outcome = "; " + std::string{wording.outcome};
    const std::string* name = string_at(folder, "name");
    if (name == nullptr || *name != kRestoreTargetName) {
        throw WrongTargetError("the OneDrive item test_onedrive_folder_id names is " +
                               quoted_name(folder) + ", not \"RestoreTarget\": the Worker " +
                               std::string{wording.only} + " the RestoreTarget folder" + outcome);
    }
    const auto facet = folder.find("folder");
    if (facet == folder.end() || !facet->is_object()) {
        throw WrongTargetError(
            "the OneDrive item test_onedrive_folder_id names is not a folder" + outcome);
    }
    const auto parent = folder.find("parentReference");
    const json none;
    const json& reference = parent == folder.end() ? none : *parent;
    const std::string* parent_drive = string_at(reference, "driveId");
    if (parent_drive == nullptr || *parent_drive != drive_id) {
        throw WrongTargetError("the OneDrive folder test_onedrive_folder_id names is not in the "
                               "drive test_onedrive_drive_id names" + outcome);
    }
    // A site library's drive (the RestoreTest library's, say) is "documentLibrary":
    // a RestoreTarget folder at its root would pass every other check.
    const std::string* drive_type = string_at(reference, "driveType");
    if (drive_type == nullptr || *drive_type != "business") {
        throw WrongTargetError("the drive test_onedrive_drive_id names is not a OneDrive (Graph's "
                               "driveType is not \"business\"): a site library's folder is never "
                               "read as the test OneDrive's" + outcome);
    }
    const std::string* path = string_at(reference, "path");
    if (path == nullptr) {
        throw WrongTargetError("Graph's reply for the OneDrive folder test_onedrive_folder_id "
                               "names has no parentReference.path; the Worker can't check it is "
                               "at the drive's root" + outcome);
    }
    // Graph writes the root either way (the recorded reply has the second).
    if (*path != "/drive/root:" && *path != "/drives/" + drive_id + "/root:") {
        throw WrongTargetError("the OneDrive folder test_onedrive_folder_id names is not directly "
                               "under the drive's root" + outcome);
    }
    // W2.7: Veeam's OneDrive ID starts with this site's GUID (restore-flow §16).
    const std::string* site = string_at(reference, "siteId");
    if (site == nullptr || !is_uuid(*site)) {
        throw WrongTargetError("Graph's reply for the OneDrive folder test_onedrive_folder_id "
                               "names has no parentReference.siteId; the Worker can't tell the "
                               "OneDrive apart" + outcome);
    }
    ResolvedOneDriveFolder resolved{*name, drive_id, targets.onedrive_folder_id(), *site};
    return resolved;
}

} // namespace rp::graph
