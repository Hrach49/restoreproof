#include <rp/target_guard.hpp>

#include <rp/config.hpp>
#include <rp/redact.hpp>

#include "folder_path.hpp"
#include "target_guard_refuse.hpp"
#include "text_util.hpp"
#include "uuid.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace rp {

namespace {

// How the shared Graph checks word a refusal here.
constexpr graph::TargetCheckWording kGuardWording{"restores only into", "nothing was restored"};

constexpr std::string_view kNothingRestored = "; nothing was restored";

} // namespace

connector::SafetyViolation refusal(const TargetGuardOptions& options, const std::string& message)
{
    // May be null: spdlog::drop_all() and shutdown() clear the default logger.
    const std::shared_ptr<spdlog::logger> logger =
        options.logger ? options.logger : spdlog::default_logger();
    if (logger) {
        logger->critical("SECURITY: {}", redact(message));
    }
    return connector::SafetyViolation(message);
}

CheckedTargets::CheckedTargets(connector::RestoreTargets configured)
    : configured_(std::move(configured))
{
}

TargetGuard::TargetGuard(graph::GraphClient& graph, TargetGuardOptions options)
    : graph_(graph), options_(std::move(options))
{
}

CheckedTargets TargetGuard::check_spec(const connector::RestoreSpec& spec)
{
    const auto refused = [this](const std::string& item, std::string_view why) {
        return refusal(options_, "target guard: " + item + std::string{why} +
                                     std::string{kNothingRestored});
    };
    // Each item first: nothing sampled from a restore target, before any call.
    for (std::size_t i = 0; i < spec.mail.size(); ++i) {
        const connector::MailSelector& item = spec.mail[i];
        const std::string which = "mail item " + std::to_string(i);
        if (item.mailbox.empty() || item.folder.empty()) {
            throw refused(which, " names no source mailbox or folder");
        }
        // Every restoretest mailbox is a restore target, the configured one
        // (which RestoreTargets allows no other than) in any case included.
        if (is_restore_mailbox(item.mailbox)) {
            throw refused(which, " is sampled from a restore target (a restoretest mailbox)");
        }
    }
    for (std::size_t i = 0; i < spec.sharepoint.size(); ++i) {
        const connector::SharePointSelector& item = spec.sharepoint[i];
        const std::string which = "sharepoint item " + std::to_string(i);
        if (item.drive_id.empty() || item.name.empty()) {
            throw refused(which, " names no source library or file");
        }
        if (ascii_iequals(item.drive_id, spec.targets.library_id())) {
            throw refused(which,
                          " is sampled from a restore target (the library test_library_id names)");
        }
        // W2.5 finds the source library by its list ID: it must be one.
        if (!is_uuid(item.list_id)) {
            throw refused(which, "'s list_id isn't a GUID");
        }
    }
    for (std::size_t i = 0; i < spec.onedrive.size(); ++i) {
        const connector::OneDriveSelector& item = spec.onedrive[i];
        const std::string which = "onedrive item " + std::to_string(i);
        if (item.user.empty() || item.name.empty()) {
            throw refused(which, " names no owner or file");
        }
        // By path: the owner can't be tied to the test OneDrive without a call.
        const std::optional<std::string_view> folder = first_folder(item.folder_path);
        if (!folder) {
            throw refused(which, "'s folder path has a \"..\" segment");
        }
        if (ascii_iequals(*folder, graph::kRestoreTargetName)) {
            throw refused(which, " is sampled from a restore target (a RestoreTarget folder)");
        }
    }
    // Then each target the spec uses, once, through Graph: a configured value
    // proves nothing by itself, restoretest@<domain> included (it may be a live
    // mailbox's alias).
    CheckedTargets checked(spec.targets);
    std::optional<std::string> wrong;
    try {
        if (!spec.mail.empty()) {
            checked.mailbox_ = graph::check_restore_mailbox(graph_, spec.targets, kGuardWording);
        }
        if (!spec.sharepoint.empty()) {
            checked.library_ = graph::check_restore_library(graph_, spec.targets, kGuardWording);
        }
        if (!spec.onedrive.empty()) {
            checked.onedrive_folder_ =
                graph::check_restore_onedrive_folder(graph_, spec.targets, kGuardWording);
        }
    } catch (const graph::WrongTargetError& e) {
        wrong = e.what();
    }
    if (wrong) {
        throw refusal(options_, "target guard: " + *wrong);
    }
    // The RestoreTarget library is in every backup since it was made: never a
    // source, whatever drive ID the item names.
    for (std::size_t i = 0; i < spec.sharepoint.size(); ++i) {
        if (ascii_iequals(spec.sharepoint[i].list_id, checked.library_->list_id)) {
            throw refused("sharepoint item " + std::to_string(i),
                          " is sampled from a restore target (the RestoreTarget library's list)");
        }
    }
    return checked;
}

} // namespace rp
