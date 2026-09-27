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
    targets.site_id_ = require_set(config.test_site_id, "test_site_id");
    targets.library_id_ = require_set(config.test_library_id, "test_library_id");
    targets.onedrive_drive_id_ = require_set(config.test_onedrive_drive_id, "test_onedrive_drive_id");
    targets.onedrive_folder_id_ =
        require_set(config.test_onedrive_folder_id, "test_onedrive_folder_id");
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

} // namespace rp::connector
