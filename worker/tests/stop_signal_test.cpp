// W4.7: rp::StopSignal (rp/stop_signal.hpp), the stop a service's control
// handler asks for and its work waits on. The real event. A waiter is another
// std::thread, which only records what it saw: no Catch2 assertion runs there.
// A wait that must not end is given no chance to be seen ending by luck: the
// signal is asked for only after the waiter has said it is about to wait, and
// what is asserted is the answer, never how long it took, except where a
// timeout is the thing tested.

#include <rp/stop_signal.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <thread>
#include <type_traits>
#include <vector>

using namespace std::chrono_literals;

// Failure paths first: a wait that nobody ends.
TEST_CASE("a stop signal nobody asked for is not requested and its timed wait runs out",
          "[stop_signal]")
{
    const rp::StopSignal stop;

    CHECK_FALSE(stop.requested());
    CHECK_FALSE(stop.wait_for(0ms));

    const auto before = std::chrono::steady_clock::now();
    CHECK_FALSE(stop.wait_for(50ms));
    // Windows may end a wait a clock tick early, never by half of it.
    CHECK(std::chrono::steady_clock::now() - before >= 25ms);
    CHECK_FALSE(stop.requested());
}

TEST_CASE("a stop signal reads a negative wait as no wait", "[stop_signal]")
{
    rp::StopSignal stop;

    CHECK_FALSE(stop.wait_for(-1ms));
    CHECK_FALSE(stop.wait_for(std::chrono::milliseconds::min()));
    stop.request();
    CHECK(stop.wait_for(-1ms));
}

TEST_CASE("a stop signal's longest wait is a wait and not no wait at all", "[stop_signal]")
{
    // Past Windows' 32-bit milliseconds, where a cut-off number would read as
    // a short wait or as "for ever": the waiter is still there after a moment
    // and is let go by the request.
    rp::StopSignal stop;
    std::promise<void> waiting;
    std::future<void> is_waiting = waiting.get_future();
    std::future<bool> answer = std::async(std::launch::async, [&stop, &waiting] {
        waiting.set_value();
        return stop.wait_for(std::chrono::milliseconds::max());
    });
    is_waiting.get();

    CHECK(answer.wait_for(100ms) == std::future_status::timeout);
    stop.request();
    CHECK(answer.get());
}

TEST_CASE("a requested stop signal stays requested and ends every wait at once", "[stop_signal]")
{
    rp::StopSignal stop;

    stop.request();

    CHECK(stop.requested());
    // Ten minutes that are never waited.
    const auto before = std::chrono::steady_clock::now();
    CHECK(stop.wait_for(10min));
    stop.wait();
    CHECK(std::chrono::steady_clock::now() - before < 1min);
    // Manual reset: a wait doesn't use the request up.
    CHECK(stop.requested());
    CHECK(stop.wait_for(0ms));

    // Asked twice is asked.
    stop.request();
    CHECK(stop.requested());
}

TEST_CASE("request() lets a waiter on another thread go", "[stop_signal]")
{
    rp::StopSignal stop;
    std::promise<void> waiting;
    std::future<void> is_waiting = waiting.get_future();
    std::atomic<bool> released{false};
    std::thread waiter([&stop, &waiting, &released] {
        waiting.set_value();
        stop.wait();
        released = true;
    });
    is_waiting.get();

    // It waits: nothing has asked yet.
    std::this_thread::sleep_for(50ms);
    CHECK_FALSE(released.load());

    stop.request();
    waiter.join();
    CHECK(released.load());
}

TEST_CASE("request() lets every waiter go, the timed ones answering true", "[stop_signal]")
{
    rp::StopSignal stop;
    std::vector<std::future<bool>> answers;
    std::vector<std::promise<void>> waiting(4);
    for (std::promise<void>& one : waiting) {
        answers.push_back(std::async(std::launch::async, [&stop, &one] {
            one.set_value();
            return stop.wait_for(10min);
        }));
    }
    for (std::promise<void>& one : waiting) {
        one.get_future().get();
    }

    stop.request();

    for (std::future<bool>& answer : answers) {
        REQUIRE(answer.wait_for(1min) == std::future_status::ready);
        CHECK(answer.get());
    }
}

TEST_CASE("request() may come from any thread, as a control handler's does", "[stop_signal]")
{
    rp::StopSignal stop;
    std::thread handler([&stop] { stop.request(); });
    handler.join();

    CHECK(stop.requested());
    CHECK(stop.wait_for(10min));
}

TEST_CASE("a stop signal is one event: not copied, not moved, and request() can't throw",
          "[stop_signal]")
{
    STATIC_CHECK_FALSE(std::is_copy_constructible_v<rp::StopSignal>);
    STATIC_CHECK_FALSE(std::is_copy_assignable_v<rp::StopSignal>);
    STATIC_CHECK_FALSE(std::is_move_constructible_v<rp::StopSignal>);
    STATIC_CHECK(noexcept(std::declval<rp::StopSignal&>().request()));
    STATIC_CHECK(noexcept(std::declval<const rp::StopSignal&>().requested()));
    STATIC_CHECK(noexcept(std::declval<const rp::StopSignal&>().wait()));
    STATIC_CHECK(noexcept(std::declval<const rp::StopSignal&>().wait_for(1ms)));
}
