#pragma once

// The checks that the configured file targets are the dedicated restore
// targets, through Graph (W2.2, shared since W2.7). A configured ID proves
// nothing by itself: a live library's drive ID has the right shape and
// resolves to a real name (this tenant's default library is "Dokumenty"). So
// each check reads the drive or folder the configured ID names and requires
// the fixed name, place and kind of a RestoreTarget (docs/decisions.md
// 2026-09-28, W2.2 and its review; 2026-09-29, W2.4 review).
// rp::graph::TargetReader runs them before it lists a file target, and
// rp::TargetGuard (rp/target_guard.hpp) before any restore; a refusal is a
// WrongTargetError there, a connector::SafetyViolation here. Only reads.

#include <rp/connector.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_errors.hpp>

#include <string>
#include <string_view>

namespace rp::graph {

// The name both file targets must have (docs/decisions.md 2026-09-25).
inline constexpr std::string_view kRestoreTargetName = "RestoreTarget";

// A refusal: the configured drive or folder is not a RestoreTarget of the
// test site or OneDrive, the canaries' RestoreTest included. Nothing was
// listed or restored; the run's status is `error`.
class WrongTargetError : public GraphError {
public:
    using GraphError::GraphError;
};

// How a refusal's message ends, for the caller that ran the check:
// "...: the Worker <only> the RestoreTarget library; <outcome>".
struct TargetCheckWording {
    std::string_view only = "reads only";
    std::string_view outcome = "nothing was listed";
};

// What the library check established. Every field comes from Graph's reply for
// the drive test_library_id names.
struct ResolvedLibrary {
    std::string name;     // exactly kRestoreTargetName
    std::string drive_id; // test_library_id
    std::string list_id;  // sharePointIds.listId, a GUID
    std::string site_id;  // sharePointIds.siteId: test_site_id's site collection GUID
    std::string web_id;   // sharePointIds.webId: test_site_id's web GUID
    std::string site_url; // sharePointIds.siteUrl, as Graph wrote it
};

// What the OneDrive folder check established, from Graph's reply for the item
// test_onedrive_folder_id names.
struct ResolvedOneDriveFolder {
    std::string name;      // exactly kRestoreTargetName
    std::string drive_id;  // test_onedrive_drive_id (parentReference.driveId)
    std::string folder_id; // test_onedrive_folder_id
    std::string site_id;   // parentReference.siteId, a GUID: the OneDrive's site
};

// GET /drives/{test_library_id}?$select=id,name,driveType,webUrl,sharePointIds.
// Throws WrongTargetError unless the drive's display name is exactly
// "RestoreTarget", the last segment of its webUrl is RestoreTarget (ignoring
// case, query, fragment and percent-encoding: a UI rename keeps the URL),
// driveType is "documentLibrary", sharePointIds.siteId and .webId are the
// GUIDs in test_site_id, sharePointIds.listId is a GUID and .siteUrl a string.
// Every missing field fails closed. Graph's own errors keep their W2.1 types.
ResolvedLibrary check_restore_library(GraphClient& graph, const connector::RestoreTargets& targets,
                                      const TargetCheckWording& wording = {});

// GET /drives/{test_onedrive_drive_id}/items/{test_onedrive_folder_id}
// ?$select=id,name,folder,parentReference. Throws WrongTargetError unless the
// item is named exactly "RestoreTarget", is a folder, sits in the drive
// test_onedrive_drive_id names, whose driveType is "business" (a site
// library's drive is "documentLibrary"), directly under its root
// (parentReference.path "/drive/root:" or "/drives/{drive}/root:"), and
// parentReference.siteId is a GUID. A 404 is a NotFoundError that adds that
// the Worker app may lack kOneDriveReadGrant: SharePoint answers 404, not 403,
// for an item the app may not read.
ResolvedOneDriveFolder check_restore_onedrive_folder(GraphClient& graph,
                                                     const connector::RestoreTargets& targets,
                                                     const TargetCheckWording& wording = {});

} // namespace rp::graph
