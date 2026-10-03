// W3.4: one run at a time on the restore targets (rp/run_lock.hpp). The real
// named mutex, under a name of this test's own, so a run of the Worker on this
// machine is never in the way and a test never holds the real one. A holder
// that isn't this thread is another std::thread: Windows mutexes are recursive,
// so this thread would get its own again. No Catch2 assertion runs on those
// threads. Failure paths first: taken, abandoned, a name Windows refuses.

#include <rp/run_lock.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <future>
#include <memory>
#include <random>
#include <string>
#include <system_error>
#include <thread>

namespace {

// A mutex name no other test or run uses.
std::wstring unique_name()
{
    std::random_device random;
    return L"Local\\RestoreProof-run-lock-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
           std::to_wstring(random());
}

// A thread that holds the lock until `release` is set, then ends.
struct Holder {
    explicit Holder(const std::wstring& name)
    {
        std::promise<bool> taken;
        std::future<bool> result = taken.get_future();
        thread = std::thread([this, name, taken = std::move(taken)]() mutable {
            std::unique_ptr<rp::RunLock> lock;
            try {
                lock = rp::try_take_named_lock(name);
            } catch (...) {
            }
            taken.set_value(lock != nullptr);
            release.wait(false);
        });
        held = result.get();
    }

    ~Holder()
    {
        release = true;
        release.notify_all();
        thread.join();
    }

    std::atomic<bool> release{false};
    std::thread thread;
    bool held = false;
};

} // namespace

TEST_CASE("run lock: a lock another holder has is taken: null, no wait", "[run_lock]")
{
    const std::wstring name = unique_name();
    Holder holder(name);
    REQUIRE(holder.held);

    CHECK(rp::try_take_named_lock(name) == nullptr);
    CHECK(rp::try_take_named_lock(name) == nullptr);
}

TEST_CASE("run lock: a lock whose holder ended without releasing it refuses once, as abandoned",
          "[run_lock]")
{
    const std::wstring name = unique_name();
    // Keeps the mutex alive after the holder's thread ends.
    HANDLE keep = CreateMutexW(nullptr, FALSE, name.c_str());
    REQUIRE(keep != nullptr);
    std::thread crashed([&name] {
        HANDLE handle = CreateMutexW(nullptr, FALSE, name.c_str());
        if (handle != nullptr) {
            WaitForSingleObject(handle, 0);
            CloseHandle(handle); // ends owning it: abandoned
        }
    });
    crashed.join();

    // Not "another run has it": that run is gone (W3.4 build notes).
    CHECK_THROWS_AS(rp::try_take_named_lock(name), rp::AbandonedRunLock);
    // Let go at once: the next run gets it.
    CHECK(rp::try_take_named_lock(name) != nullptr);
    CloseHandle(keep);
}

TEST_CASE("run lock: a name Windows can't make a mutex of throws", "[run_lock]")
{
    // A backslash after the namespace prefix is refused (ERROR_PATH_NOT_FOUND).
    CHECK_THROWS_AS(rp::try_take_named_lock(L"Local\\RestoreProof\\no-such-namespace\\x"),
                    std::system_error);
}

TEST_CASE("run lock: a free lock is taken, held while it lives and released after", "[run_lock]")
{
    const std::wstring name = unique_name();
    {
        const std::unique_ptr<rp::RunLock> lock = rp::try_take_named_lock(name);
        REQUIRE(lock != nullptr);
        Holder other(name);
        CHECK_FALSE(other.held);
    }
    Holder after(name);
    CHECK(after.held);
}

TEST_CASE("run lock: the restore targets' mutex is a Global one of its own name", "[run_lock]")
{
    CHECK(rp::kRestoreTargetsMutex == L"Global\\RestoreProof-restore-targets");
    // Taken and given back at once; a run of the Worker on this machine makes
    // it null, which is no failure here.
    const std::unique_ptr<rp::RunLock> lock = rp::try_take_restore_targets_lock();
    SUCCEED();
}
