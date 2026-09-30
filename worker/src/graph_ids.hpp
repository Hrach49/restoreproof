#pragma once

// Graph IDs the Worker works out itself instead of reading them (W2.6;
// docs/decisions.md 2026-09-30, W2.6 point 8): the Worker app reads the restore
// targets only, so a random SharePoint item's drive ID comes from the GUIDs
// Veeam shows.

#include <optional>
#include <string>
#include <string_view>

namespace rp {

// A document library's Graph drive ID: "b!" and the base64url, without
// padding, of the site, web and list GUIDs' little-endian bytes (48 bytes; for
// aabbccdd-eeff-gghh-iijj-kkllmmnnoopp, dd cc bb aa ff ee hh gg ii jj kk ll mm
// nn oo pp). It gives the lab's canary library, RestoreTarget library
// (test_library_id) and alice's OneDrive the drive IDs Graph gave them. The
// GUIDs may be in any case; nullopt unless all three are UUIDs.
std::optional<std::string> graph_drive_id(std::string_view site_guid, std::string_view web_guid,
                                          std::string_view list_guid);

} // namespace rp
