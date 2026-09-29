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
    std::string web_id;    // sharepointIds.webId, a GUID: the OneDrive's web
    std::string site_url;  // sharepointIds.siteUrl, as Graph wrote it: the OneDrive's address
};

// What the mailbox check established: Graph let the Worker app read the Inbox
// of the address test_mailbox names.
struct ResolvedMailbox {
    std::string address;  // test_mailbox, as configured
    std::string inbox_id; // the Inbox folder's ID, as Graph wrote it
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
// ?$select=id,name,folder,parentReference,sharepointIds. Throws WrongTargetError unless the
// item is named exactly "RestoreTarget", is a folder, sits in the drive
// test_onedrive_drive_id names, whose driveType is "business" (a site
// library's drive is "documentLibrary"), directly under its root
// (parentReference.path "/drive/root:" or "/drives/{drive}/root:"),
// parentReference.siteId is a GUID, and sharepointIds has that siteId (ASCII
// case-insensitive), a GUID webId and a string siteUrl: the address a OneDrive
// restore names (W2.7). A 404 is a NotFoundError that adds that
// the Worker app may lack kOneDriveReadGrant: SharePoint answers 404, not 403,
// for an item the app may not read.
ResolvedOneDriveFolder check_restore_onedrive_folder(GraphClient& graph,
                                                     const connector::RestoreTargets& targets,
                                                     const TargetCheckWording& wording = {});

// GET /users/{test_mailbox}/mailFolders/inbox?$select=id (W2.7). The Worker app
// reads mail only through Exchange RBAC "Application Mail.Read" in a management
// scope of the restoretest mailbox's primary address alone
// (docs/security/graph-permissions.md, #3), so a 200 shows the configured
// address reaches that mailbox, not a live mailbox holding the name as an
// alias. Graph's 403 for it is a WrongTargetError (another mailbox, or the
// scope is missing); so is a reply without a string id. Graph's other errors
// keep their W2.1 types (a 404: no such mailbox).
ResolvedMailbox check_restore_mailbox(GraphClient& graph, const connector::RestoreTargets& targets,
                                      const TargetCheckWording& wording = {});

} // namespace rp::graph
