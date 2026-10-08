#include <rp/stop_signal.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <system_error>

namespace rp {

namespace {

// The longest single wait asked of Windows: INFINITE is the number after the
// last real one, so a longer wait is made of several.
constexpr std::chrono::milliseconds kLongestWait{INFINITE - 1};

} // namespace

StopSignal::StopSignal()
    // Manual reset, not set, no name: nothing outside this process opens it.
    : event_(CreateEventW(nullptr, TRUE, FALSE, nullptr))
{
    if (event_ == nullptr) {
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                "CreateEventW");
    }
}

StopSignal::~StopSignal()
{
    CloseHandle(event_);
}

void StopSignal::request() noexcept
{
    SetEvent(event_);
}

bool StopSignal::requested() const noexcept
{
    return WaitForSingleObject(event_, 0) == WAIT_OBJECT_0;
}

void StopSignal::wait() const noexcept
{
    WaitForSingleObject(event_, INFINITE);
}

bool StopSignal::wait_for(std::chrono::milliseconds time) const noexcept
{
    bool stopped = requested();
    while (!stopped && time > std::chrono::milliseconds::zero()) {
        const std::chrono::milliseconds slice = std::min(time, kLongestWait);
        stopped = WaitForSingleObject(event_, static_cast<DWORD>(slice.count())) == WAIT_OBJECT_0;
        time -= slice;
    }
    return stopped;
}

} // namespace rp
