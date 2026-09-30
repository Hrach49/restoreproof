#include <rp/connector.hpp>

#include <stdexcept>
#include <string>
#include <string_view>

namespace rp::connector {

namespace {

const std::string& require_set(const std::string& value, std::string_view key)
{
    if (value.empty()) {
        throw std::invalid_argument("restore target " + std::string{key} + " is empty");
    }
    return value;
}

} // namespace

RestoreTargets RestoreTargets::from_config(const Config& config)
{
    RestoreTargets targets;
    targets.mailbox_ = require_set(config.test_mailbox, "test_mailbox");
    // The same rule parse_config applies: never a mailbox other than restoretest.
    if (!is_restore_mailbox(targets.mailbox_)) {
        throw std::invalid_argument("restore target test_mailbox must be restoretest@<domain>");
    }
    targets.site_id_ = require_set(config.test_site_id, "test_site_id");
    targets.library_id_ = require_set(config.test_library_id, "test_library_id");
    targets.onedrive_drive_id_ = require_set(config.test_onedrive_drive_id, "test_onedrive_drive_id");
    targets.onedrive_folder_id_ =
        require_set(config.test_onedrive_folder_id, "test_onedrive_folder_id");
    // The shapes parse_config applies: the IDs go into Graph URL paths.
    const auto check = [](bool ok, std::string_view key, std::string_view rule) {
        if (!ok) {
            throw std::invalid_argument("restore target " + std::string{key} + " " +
                                        std::string{rule});
        }
    };
    check(parse_graph_site_id(targets.site_id_).has_value(), "test_site_id", kGraphSiteIdRule);
    check(is_graph_drive_id(targets.library_id_), "test_library_id", kGraphDriveIdRule);
    check(is_graph_drive_id(targets.onedrive_drive_id_), "test_onedrive_drive_id",
          kGraphDriveIdRule);
    check(is_graph_item_id(targets.onedrive_folder_id_), "test_onedrive_folder_id",
          kGraphItemIdRule);
    return targets;
}

std::string_view to_string(RestoreStatus status) noexcept
{
    switch (status) {
    case RestoreStatus::succeeded:
        return "succeeded";
    case RestoreStatus::partial:
        return "partial";
    case RestoreStatus::failed:
        return "failed";
    case RestoreStatus::not_run:
        break;
    }
    return "not_run";
}

std::string_view to_string(ItemKind kind) noexcept
{
    switch (kind) {
    case ItemKind::sharepoint:
        return "sharepoint";
    case ItemKind::onedrive:
        return "onedrive";
    case ItemKind::mail:
        break;
    }
    return "mail";
}

std::string_view to_string(ItemOutcome outcome) noexcept
{
    switch (outcome) {
    case ItemOutcome::restored:
        return "restored";
    case ItemOutcome::failed:
        return "failed";
    case ItemOutcome::unknown:
        break;
    }
    return "unknown";
}

CandidatePool IConnector::list_candidates(const CandidateQuery& /*query*/)
{
    throw NotImplementedError(describe().name + ": listing candidates isn't implemented");
}

} // namespace rp::connector
