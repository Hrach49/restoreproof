#pragma once

// The stop a service is asked for (W4.7, docs/decisions.md 2026-10-08 point 5):
// one manual-reset event. The service's control handler calls request(), which
// takes no lock and never blocks; the service's work waits on it, or asks it
// between two steps. Once asked for, a stop stays asked for: nothing takes it
// back, and a wait doesn't use it up.
//
// It is also the stop source W4.4 and W4.6 left open: W4.8's interruptible
// sleep is wait_for, handed to the pipeline as ConnectorOptions::sleep, so a
// retry's or a poll's wait ends at once when the service is stopped.
//
// No Windows type is named here; the event lives in src/stop_signal.cpp.

#include <chrono>

namespace rp {

class StopSignal {
public:
    // Throws std::system_error when Windows can't make the event.
    StopSignal();
    ~StopSignal();

    // One event, shared by reference (the service hands its context on as a
    // shared_ptr): a copy would be a second event nobody sets.
    StopSignal(const StopSignal&) = delete;
    StopSignal& operator=(const StopSignal&) = delete;

    // Asks for the stop: one call that sets the event. No lock, no
    // allocation, never blocks, from any thread; asking twice is asking once.
    void request() noexcept;

    // Whether a stop was asked for.
    bool requested() const noexcept;

    // Returns when a stop is asked for; at once when it already was.
    void wait() const noexcept;

    // Waits up to `time` for a stop. True when one was asked for, at once
    // when it already was; false when the time ran out first. A negative
    // time is no wait at all: the answer is requested().
    bool wait_for(std::chrono::milliseconds time) const noexcept;

private:
    // The event's handle (a Windows HANDLE).
    void* event_;
};

} // namespace rp
