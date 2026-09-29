#pragma once

// The restore-target guard (W2.7), layer 1: before any call to the backup
// product, inside restore_sample, every item of a RestoreSpec is checked, and
// the configured targets are resolved through Graph and checked to be the
// dedicated restore targets (CLAUDE.md, "Restore targets"; docs/decisions.md
// 2026-09-22 and 2026-09-29, W2.4 review). Configured IDs are never trusted
// alone: a live library's drive ID has the right shape too. Layer 2, on the
// exact restore request, is the backup product's (Veeam's:
// rp/target_guard_veeam.hpp) and takes this layer's CheckedTargets, so it can't
// run without it. Nothing here names a backup product.
//
// A refusal is a connector::SafetyViolation (status `error`, never `fail`;
// exit code 4), logged once at critical level as "SECURITY: <message>"
// through rp::redact. Its message starts with "target guard: ", names the item
// by its type and index, and never holds a credential.

#include <rp/connector.hpp>
#include <rp/graph_client.hpp>
#include <rp/target_guard_graph.hpp>

#include <spdlog/logger.h>

#include <memory>
#include <optional>
#include <string>

namespace rp {

struct TargetGuardOptions {
    // Where each refusal's one line goes; null: spdlog::default_logger()
    // (which spdlog::drop_all() may have cleared: then nothing is logged).
    std::shared_ptr<spdlog::logger> logger;
};

// What layer 1 established about the restore targets. Only TargetGuard makes
// one, and only when every check passed.
class CheckedTargets {
public:
    // The configured targets, as the spec carried them.
    const connector::RestoreTargets& configured() const noexcept { return configured_; }
    // The mail target: the configured restoretest@<domain>, as configured
    // (RestoreTargets::from_config allows no other); its folder is Inbox.
    const std::string& mailbox() const noexcept { return configured_.mailbox(); }
    // The RestoreTarget library; set only when the spec had SharePoint items.
    const std::optional<graph::ResolvedLibrary>& library() const noexcept { return library_; }
    // The test OneDrive's RestoreTarget folder; set only when the spec had
    // OneDrive items.
    const std::optional<graph::ResolvedOneDriveFolder>& onedrive_folder() const noexcept
    {
        return onedrive_folder_;
    }

private:
    friend class TargetGuard;
    explicit CheckedTargets(connector::RestoreTargets configured);

    connector::RestoreTargets configured_;
    std::optional<graph::ResolvedLibrary> library_;
    std::optional<graph::ResolvedOneDriveFolder> onedrive_folder_;
};

// `graph` is the Worker app's client (read-only calls) and must outlive the
// guard.
class TargetGuard {
public:
    explicit TargetGuard(graph::GraphClient& graph, TargetGuardOptions options = {});

    // Layer 1. First each item, in the spec's order (mail, SharePoint,
    // OneDrive), without a call:
    //  - mail: a source mailbox and folder are named, and the mailbox is no
    //    restoretest mailbox (rp::is_restore_mailbox, any case), the test
    //    mailbox included;
    //  - SharePoint: a source drive and file are named, and the drive is not
    //    test_library_id (ASCII case-insensitive);
    //  - OneDrive: an owner and file are named, and the folder path has no
    //    ".." segment and doesn't start with a RestoreTarget folder (ASCII
    //    case-insensitive, empty and "." segments skipped). The owner can't be
    //    tied to the test OneDrive without a call W2.5 makes anyway, so this
    //    rule is by path.
    // Then, once per type the spec uses, the target through Graph (GETs only;
    // mail needs none): check_restore_library and
    // check_restore_onedrive_folder, whose WrongTargetError becomes a
    // SafetyViolation with the same text. Graph's other errors pass through
    // with their own types (AuthError, PermissionError, NotFoundError,
    // TransientError: `error` all the same). An empty spec checks nothing and
    // resolves nothing (restore_sample reports not_run).
    CheckedTargets check_spec(const connector::RestoreSpec& spec);

private:
    graph::GraphClient& graph_;
    TargetGuardOptions options_;
};

} // namespace rp
