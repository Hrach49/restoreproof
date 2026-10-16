#pragma once

// The lab's tenant, Worker app and restore targets (lab/tenant.md, "Restore
// targets") for the Graph [live] tests, each overridable by an RP_LIVE_*
// variable (docs/testing.md, "Live tests"). No canary location is named here:
// the canaries' IDs and paths come from lab/seed-manifest.json. Under worker/
// the canary folder appears only by its name, "RestoreTest", as a place a
// random sample and a restore must never touch (the sampler and the lister,
// docs/decisions.md 2026-09-30 W2.6 point 6; the target guard's forbidden
// names), and in tests.

#include "test_support.hpp"

#include <rp/config.hpp>

#include <optional>
#include <string>

namespace rp::test::graph_live {

inline const std::string kLabTenantId = "bcd6bd1a-ea42-489d-aa28-2c19a44ad146";
inline const std::string kLabWorkerClientId = "de8d4348-08a9-48ee-a04a-47c7189c5006";
inline const std::string kLabMailbox = "restoretest@RestoreProofLab.onmicrosoft.com";
inline const std::string kLabSiteId = "restoreprooflab.sharepoint.com,"
                                      "fe08085d-eb70-42e8-95a6-470189bd98eb,"
                                      "4ecaf399-cc0e-4d95-b3fe-cd091a09e689";
inline const std::string kLabLibraryDriveId =
    "b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5okL098pI5L8SauHogWnV_iW";
inline const std::string kLabOneDriveDriveId =
    "b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3";
inline const std::string kLabOneDriveFolderId = "01ZK75LGEIWSMV5NCPERHJYGWANJI7YUFB";

// The variable's value, or `fallback` when it is unset or empty.
inline std::string env_or(const char* name, const std::string& fallback)
{
    const std::optional<std::string> value = get_env(name);
    return value && !value->empty() ? *value : fallback;
}

// Whether RP_LIVE=1: a [live] test SKIPs otherwise.
inline bool live_enabled()
{
    return get_env("RP_LIVE") == std::optional<std::string>{"1"};
}

inline std::string live_tenant_id()
{
    return env_or("RP_LIVE_GRAPH_TENANT_ID", kLabTenantId);
}

inline std::string live_client_id()
{
    return env_or("RP_LIVE_GRAPH_CLIENT_ID", kLabWorkerClientId);
}

// A Config holding the tenant, the app and the five restore-target values.
inline rp::Config live_config()
{
    rp::Config config;
    config.graph_tenant_id = live_tenant_id();
    config.graph_client_id = live_client_id();
    config.test_mailbox = env_or("RP_LIVE_TARGET_MAILBOX", kLabMailbox);
    config.test_site_id = env_or("RP_LIVE_TARGET_SITE_ID", kLabSiteId);
    config.test_library_id = env_or("RP_LIVE_TARGET_LIBRARY_ID", kLabLibraryDriveId);
    config.test_onedrive_drive_id =
        env_or("RP_LIVE_TARGET_ONEDRIVE_DRIVE_ID", kLabOneDriveDriveId);
    config.test_onedrive_folder_id =
        env_or("RP_LIVE_TARGET_ONEDRIVE_FOLDER_ID", kLabOneDriveFolderId);
    return config;
}

} // namespace rp::test::graph_live
