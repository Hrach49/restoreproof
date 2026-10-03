#pragma once

// One run at a time on the restore targets (W3.4, docs/decisions.md
// 2026-10-02 point 8): `rpworker restore` takes a machine-wide named mutex
// before its first Veeam call and holds it until it exits, so one run's
// cleanup can never delete another run's copies between that run's restore and
// its read-back (its items would read `missing`: a false `fail`). The two
// [live][writes] tests take it too; `graph list`, which only reads, doesn't.

#include <memory>
#include <stdexcept>
#include <string_view>

namespace rp {

// The mutex's name: in the Global namespace, so runs in other sessions (a
// service, another user's shell) see it too.
inline constexpr std::wstring_view kRestoreTargetsMutex = L"Global\\RestoreProof-restore-targets";

// Held while it lives; released when it is destroyed, on the thread that took it.
class RunLock {
public:
    virtual ~RunLock() = default;
};

// Thrown by try_take_named_lock when the mutex's last holder ended without
// releasing it (WAIT_ABANDONED, a crashed run): counted as taken for this
// try, as W3.4 point 8 says, but no other run has it, so the refusal says so.
class AbandonedRunLock : public std::runtime_error {
public:
    AbandonedRunLock() : std::runtime_error("the run mutex was abandoned by its last holder") {}
};

// Takes the named mutex `name` without waiting. Null when it is taken: another
// holder has it, or Windows refuses to open it (ERROR_ACCESS_DENIED: another
// user's run made it). Throws AbandonedRunLock when its holder ended without
// releasing it: what that run left in the targets is unknown, so this try is
// refused, and the mutex is released at once, so the next try gets it (W3.4
// build notes). A thread that already holds it gets it again (Windows mutexes
// are recursive); the command takes it once. Throws std::system_error when
// Windows can't make it or wait on it.
std::unique_ptr<RunLock> try_take_named_lock(std::wstring_view name);

// try_take_named_lock(kRestoreTargetsMutex).
std::unique_ptr<RunLock> try_take_restore_targets_lock();

} // namespace rp
