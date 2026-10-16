#include <rp/service_errors.hpp>

#include <rp/outbox.hpp>

#include <algorithm>
#include <array>

namespace rp {

namespace {

constexpr std::array kCodes{
    service_error::kJobsUnreadable,
    service_error::kJobInvalid,
    service_error::kJobNotStarted,
    service_error::kRecordNotWritten,
    service_error::kRecordNotRemoved,
    service_error::kRecordUnreadable,
    service_error::kRunNotClosed,
    service_error::kRunNotQueued,
    service_error::kFolderChanged,
    service_error::kNotRead,
    service_error::kVeeamLookFailed,
    service_error::kVeeamSessionsWorking,
    service_error::kRecoveryCleanIncomplete,
    upload_code::kUnreachable,
    upload_code::kTimeout,
    upload_code::kInternal,
    service_error::kNotRegistered,
    service_error::kTokenRefused,
    upload_code::kNotCloud,
};

} // namespace

std::span<const std::string_view> service_error_codes() noexcept
{
    return kCodes;
}

bool is_service_error(std::string_view word) noexcept
{
    return std::ranges::find(kCodes, word) != kCodes.end() || is_upload_error(word);
}

} // namespace rp
