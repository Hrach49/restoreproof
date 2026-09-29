#pragma once

// The restore-target guard (W2.7), layer 2, for Veeam Backup for Microsoft 365
// (REST API v8): immediately before a restore POST, on the exact path and body
// text about to be sent, the request must name exactly the targets layer 1
// checked (rp/target_guard.hpp) and exactly the items browsing resolved. It is
// Assert-RestoreTarget of docs/api/veeam-m365/10-restore.ps1 without its
// lab-only rules (docs/api/veeam-restore-flow.md §6, §16; docs/decisions.md
// 2026-09-29, W2.7).

#include <rp/target_guard.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace rp::veeam {

// Which restore-to-another-location call: mail restoreTo, SharePoint
// restoreTo, OneDrive copyTo.
enum class RestoreKind { mail, sharepoint, onedrive };

// One item browsing resolved: Veeam's item ID, and for a file its name ("" for
// mail).
struct GuardedItem {
    std::string id;
    std::string name;
};

// What W2.5 established with read-only calls before the POST.
struct RestoreRequestContext {
    RestoreKind kind = RestoreKind::mail;
    // The explore sessions this run opened, in order.
    std::vector<std::string> opened_explore_sessions;
    // The source mailbox's, site's or OneDrive's Veeam ID, as in the path: one
    // or more lower-case GUIDs run together.
    std::string container_id;
    // The items to restore, from the sample: at least one, no ID twice.
    std::vector<GuardedItem> items;
    // Veeam's organisation app (GET /v8/Organizations).
    std::string application_id;
    // The organisation's officeName, e.g. RestoreProofLab.onmicrosoft.com.
    std::string organization_name;
    // The organisation's region, e.g. Worldwide.
    std::string office_region;
    // OneDrive: Veeam's OneDrives entry W2.5 matched to the test OneDrive.
    std::string target_onedrive_id;
    std::string target_onedrive_name;
    std::string target_onedrive_url;
};

// Layer 2. Throws connector::SafetyViolation ("target guard: ...; the restore
// was not sent"), logged as layer 1 logs it, unless all of these hold:
//  - the context: items non-empty with no ID twice; container_id one or more
//    lower-case GUIDs; application_id, organization_name, office_region (and
//    for OneDrive target_onedrive_id and _url) non-empty printable ASCII; for
//    SharePoint and OneDrive, `targets` has the library or folder resolved;
//  - the path: no '?', '#', '%', '\\', "//" or dot segment; the explore
//    session a lower-case GUID this run opened; then exactly
//    /v8/RestoreSessions/{e}/organization/mailboxes/{c}/items/restoreTo,
//    /v8/RestoreSessions/{e}/Organization/Sites/{c}/Documents/restoreTo or
//    /v8/RestoreSessions/{e}/Organization/OneDrives/{c}/Documents/copyTo for
//    ctx.kind, with c = ctx.container_id;
//  - the body: valid UTF-8 JSON, an object at the top, no object anywhere with
//    a key twice, and exactly the kind's key set (restore-flow §5);
//  - values: JSON kinds as sent (strings, booleans, arrays, objects); each
//    value compared with a target or fixed name printable ASCII (0x20-0x7E);
//    every comparison ordinal unless said otherwise; officeRegion and
//    applicationId the context's; both credential fields JSON strings, never
//    read further;
//  - mail: mailbox and impersonationAccountName the test mailbox, folder
//    "Inbox", officeOrganizationName the organisation's, the seven flags
//    booleans, each item an object holding only a string "id";
//  - SharePoint: siteURL the library's sharePointIds.siteUrl, list the
//    library's name ("RestoreTarget") and none of RestoreTest, Documents,
//    Shared Documents; organizationName the organisation's; documentVersion
//    "Last", documentLastVersionAction "Merge", sendSharedLinksNotification
//    false; each document an object with string id and name, siteId equal to
//    container_id, isFolder false, an id that starts with container_id and not
//    with the RestoreTarget library's site, web and list GUIDs (a restore
//    target is never a source);
//  - OneDrive: onedrive an object of exactly string id, name and url, equal to
//    the context's target_onedrive_*; its id's first GUID the RestoreTarget
//    folder's parentReference.siteId (ASCII case-insensitive); its url on
//    https://<tenant>-my.sharepoint.com/ for test_site_id's tenant, with no
//    query or fragment; folder the folder's name ("RestoreTarget") and not a
//    forbidden name; organizationName and the version options as SharePoint;
//    changedItems and deletedItems booleans; each document an object with
//    string id and name, oneDriveId equal to container_id, isFolder false;
//  - the items: the body's (id, name) pairs are exactly ctx.items, none
//    missing, added or twice.
// Item IDs and names, and onedrive.name, are compared byte for byte with the
// context and may be any UTF-8: they identify, they don't name a target.
void check_restore_request(const CheckedTargets& targets, const RestoreRequestContext& ctx,
                           std::string_view path, std::string_view body,
                           const TargetGuardOptions& options = {});

} // namespace rp::veeam
