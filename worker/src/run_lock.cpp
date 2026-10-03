#include <rp/run_lock.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <system_error>

namespace rp {

namespace {

// Owns one handle to the mutex, and the mutex itself.
class NamedMutexLock final : public RunLock {
public:
    explicit NamedMutexLock(HANDLE handle) noexcept : handle_(handle) {}
    NamedMutexLock(const NamedMutexLock&) = delete;
    NamedMutexLock& operator=(const NamedMutexLock&) = delete;

    ~NamedMutexLock() override
    {
        ReleaseMutex(handle_);
        CloseHandle(handle_);
    }

private:
    HANDLE handle_;
};

[[noreturn]] void throw_last_error(const char* what)
{
    throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), what);
}

} // namespace

std::unique_ptr<RunLock> try_take_named_lock(std::wstring_view name)
{
    const std::wstring terminated{name};
    HANDLE handle = CreateMutexW(nullptr, FALSE, terminated.c_str());
    if (handle == nullptr) {
        // Another user's run made it with a DACL this process isn't on.
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            return nullptr;
        }
        throw_last_error("CreateMutexW");
    }
    switch (WaitForSingleObject(handle, 0)) {
    case WAIT_OBJECT_0:
        return std::make_unique<NamedMutexLock>(handle);
    case WAIT_ABANDONED:
        // Its holder ended mid-run: refused, as far as this run goes. This
        // thread owns it now, so it lets it go for the next try.
        ReleaseMutex(handle);
        CloseHandle(handle);
        throw AbandonedRunLock();
    case WAIT_TIMEOUT:
        CloseHandle(handle);
        return nullptr;
    default:
        break;
    }
    const DWORD error = GetLastError();
    CloseHandle(handle);
    throw std::system_error(static_cast<int>(error), std::system_category(),
                            "WaitForSingleObject");
}

std::unique_ptr<RunLock> try_take_restore_targets_lock()
{
    return try_take_named_lock(kRestoreTargetsMutex);
}

} // namespace rp
