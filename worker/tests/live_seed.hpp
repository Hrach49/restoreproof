#pragma once

// Where the live cleanup test (cleaner_live_test.cpp) may put its three seeds:
// one small file in the RestoreTarget library's root, one in alice's
// /RestoreTarget folder, one message in the restoretest Inbox. A configured
// ID is never trusted alone (docs/decisions.md 2026-09-29, W2.4 review): the
// IDs are checked for shape (RestoreTargets::from_config, parse_config's
// rules), then each target is resolved through the target guard's own Graph
// checks (rp/target_guard_graph.hpp, the ones the Cleaner's resolve() runs),
// and the seed paths are built only from what those checks established. Any
// refusal throws before the test sends a single write. Only reads Graph.

#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/graph_client.hpp>
#include <rp/target_guard_graph.hpp>

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

namespace rp::test::live_seed {

// %40 is "@", as lab/seeder/worker_app.py's create probes send it.
inline const std::string kFailOnConflict = "?%40microsoft.graph.conflictBehavior=fail";

// How a refusal's message ends here.
inline constexpr rp::graph::TargetCheckWording kSeedWording{"seeds only in",
                                                            "nothing was seeded"};

// "rp-probe-" then a lower-case UUID: the seeds' only names.
inline bool is_probe_name(std::string_view name)
{
    constexpr std::string_view prefix = "rp-probe-";
    if (!name.starts_with(prefix) || name.size() != prefix.size() + 36) {
        return false;
    }
    const std::string_view uuid = name.substr(prefix.size());
    for (std::size_t i = 0; i < uuid.size(); ++i) {
        const char c = uuid[i];
        const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

// The three seed requests, the only writes the test sends itself.
struct SeedPaths {
    std::string library;           // PUT, a file in the RestoreTarget library's root
    std::string onedrive;          // PUT, a file in alice's /RestoreTarget folder
    std::string mail;              // POST, a message in the restoretest Inbox
    std::string library_drive_id;  // as the library check established it
    std::string onedrive_drive_id; // as the folder check established it
    std::string onedrive_folder_id;
};

// Checks the configured targets' shapes, resolves all three through the
// guard's Graph checks, and only then builds the paths for `probe`
// ("rp-probe-<uuid>"; the files are "<probe>.txt"). Throws
// std::invalid_argument for a bad shape or name, WrongTargetError for a
// target that isn't a RestoreTarget, Graph's errors as they come: in every
// case before any write.
inline SeedPaths resolve_seed_paths(rp::graph::GraphClient& graph, const rp::Config& config,
                                    const std::string& probe)
{
    if (!is_probe_name(probe)) {
        throw std::invalid_argument("a seed's name must be rp-probe-<lower-case UUID>");
    }
    const rp::connector::RestoreTargets targets =
        rp::connector::RestoreTargets::from_config(config);
    const rp::graph::ResolvedMailbox mailbox =
        rp::graph::check_restore_mailbox(graph, targets, kSeedWording);
    const rp::graph::ResolvedLibrary library =
        rp::graph::check_restore_library(graph, targets, kSeedWording);
    const rp::graph::ResolvedOneDriveFolder folder =
        rp::graph::check_restore_onedrive_folder(graph, targets, kSeedWording);
    const std::string file = probe + ".txt";
    SeedPaths paths;
    paths.library = "/drives/" + library.drive_id + "/items/root:/" + file + ":/content" +
                    kFailOnConflict;
    paths.onedrive = "/drives/" + folder.drive_id + "/items/" + folder.folder_id + ":/" + file +
                     ":/content" + kFailOnConflict;
    paths.mail = "/users/" + mailbox.address + "/mailFolders/inbox/messages";
    paths.library_drive_id = library.drive_id;
    paths.onedrive_drive_id = folder.drive_id;
    paths.onedrive_folder_id = folder.folder_id;
    return paths;
}

} // namespace rp::test::live_seed
