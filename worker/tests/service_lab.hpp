#pragma once

// The running service's tests (rp::Service, W4.7 points 5 and 6): a fake
// rp::ServiceHost in place of the Service Control Manager, and a Lab with a
// temp folder for the log and the config. No test touches the machine's real
// service or %ProgramData%, and none really waits out the stop's budget.
//
// The fake host records every call in order, under a lock. Its dispatcher runs
// the service's main function on a thread of its own and returns when that
// has ended, as the real one does; the Lab calls Service::run on a third
// thread, so the test's thread is free to deliver controls (it plays the SCM's
// dispatcher thread: the handler runs on it). The service's threads only
// record; every assertion is made on the test's thread.

#include "graph_lab.hpp"
#include "test_support.hpp"

#include <rp/service.hpp>
#include <rp/service_log.hpp>
#include <rp/stop_signal.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace rp::test::service_lab {

// How long a test waits for something another thread is about to do before it
// gives up and fails. Never waited out by a test that passes.
inline constexpr std::chrono::seconds kPatience{60};

// One call into the fake host, in the order they were made.
struct HostEvent {
    enum class Kind { dispatcher_started, registered, report, exit, dispatcher_returned };
    Kind kind = Kind::report;
    // registered, dispatcher_started: the service's name as it was passed.
    std::string name;
    // report
    rp::ServiceReport report;
    // report: whether the stop was asked for when the report was made; nullopt
    // when the test's body didn't hand the fake its context.
    std::optional<bool> stop_requested;
    // exit
    int code = 0;
};

inline bool same_report(const rp::ServiceReport& a, const rp::ServiceReport& b)
{
    return a.state == b.state && a.accepts_stop == b.accepts_stop &&
           a.service_exit_code == b.service_exit_code && a.checkpoint == b.checkpoint &&
           a.wait_hint_ms == b.wait_hint_ms;
}

// "<state> accepts=<0|1> code=<n> checkpoint=<n> hint=<n>", for a test's
// failure message and for comparing whole sequences.
inline std::string text_of(const rp::ServiceReport& report)
{
    static constexpr std::string_view kStates[] = {
        "stopped", "start_pending", "stop_pending", "running",
        "continue_pending", "pause_pending", "paused",
    };
    std::ostringstream out;
    out << kStates[static_cast<std::size_t>(report.state)] << " accepts=" << report.accepts_stop
        << " code=" << report.service_exit_code << " checkpoint=" << report.checkpoint
        << " hint=" << report.wait_hint_ms;
    return out.str();
}

// Every host call as one word or line: "dispatcher", "registered",
// the report's text, "exit <code>", "dispatcher returned".
inline std::string text_of(const HostEvent& event)
{
    switch (event.kind) {
    case HostEvent::Kind::dispatcher_started:
        return "dispatcher";
    case HostEvent::Kind::registered:
        return "registered";
    case HostEvent::Kind::report:
        return text_of(event.report);
    case HostEvent::Kind::exit:
        return "exit " + std::to_string(event.code);
    case HostEvent::Kind::dispatcher_returned:
        break;
    }
    return "dispatcher returned";
}

class FakeHost {
public:
    // What the dispatcher answers without running the main function, when not
    // 0 (1063: a process the SCM didn't start).
    unsigned long dispatcher_error = 0;
    // What registering the handler answers, when not 0.
    unsigned long register_error = 0;

    // The context of the running service, once a test's body handed it over:
    // each report then records whether the stop was asked for.
    std::atomic<const rp::ServiceContext*> context{nullptr};

    rp::ServiceHost host()
    {
        rp::ServiceHost out;
        out.run_dispatcher = [this](std::string_view name, rp::ServiceMainFunction main) {
            HostEvent started;
            started.kind = HostEvent::Kind::dispatcher_started;
            started.name = std::string{name};
            add(std::move(started));
            if (dispatcher_error != 0) {
                return dispatcher_error;
            }
            // On a thread of the dispatcher's, as the SCM runs it.
            std::thread thread{std::move(main)};
            thread.join();
            HostEvent returned;
            returned.kind = HostEvent::Kind::dispatcher_returned;
            add(std::move(returned));
            return 0ul;
        };
        out.register_handler = [this](std::string_view name, rp::ServiceControlHandler handler) {
            HostEvent event;
            event.kind = HostEvent::Kind::registered;
            event.name = std::string{name};
            {
                const std::lock_guard<std::mutex> lock{mutex_};
                if (register_error == 0) {
                    handler_ = std::move(handler);
                }
                events_.push_back(std::move(event));
            }
            changed_.notify_all();
            return register_error;
        };
        out.report_status = [this](const rp::ServiceReport& report) {
            HostEvent event;
            event.kind = HostEvent::Kind::report;
            event.report = report;
            if (const rp::ServiceContext* running = context.load()) {
                event.stop_requested = running->stop.requested();
            }
            add(std::move(event));
            return 0ul;
        };
        // Records the code and returns, which the real one never does.
        out.exit_process = [this](int code) {
            HostEvent event;
            event.kind = HostEvent::Kind::exit;
            event.code = code;
            add(std::move(event));
        };
        return out;
    }

    std::vector<HostEvent> events() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return events_;
    }

    // Every call so far, as text_of gives it.
    std::vector<std::string> calls() const
    {
        std::vector<std::string> out;
        for (const HostEvent& event : events()) {
            out.push_back(text_of(event));
        }
        return out;
    }

    std::vector<HostEvent> reports() const
    {
        std::vector<HostEvent> out;
        for (const HostEvent& event : events()) {
            if (event.kind == HostEvent::Kind::report) {
                out.push_back(event);
            }
        }
        return out;
    }

    std::vector<std::string> report_texts() const
    {
        std::vector<std::string> out;
        for (const HostEvent& event : reports()) {
            out.push_back(text_of(event.report));
        }
        return out;
    }

    std::vector<int> exits() const
    {
        std::vector<int> out;
        for (const HostEvent& event : events()) {
            if (event.kind == HostEvent::Kind::exit) {
                out.push_back(event.code);
            }
        }
        return out;
    }

    bool has_handler() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return static_cast<bool>(handler_);
    }

    // Waits until a report of `state` was made; false when none came.
    bool wait_for_state(rp::ServiceState state) const
    {
        std::unique_lock<std::mutex> lock{mutex_};
        return changed_.wait_for(lock, kPatience, [&] {
            for (const HostEvent& event : events_) {
                if (event.kind == HostEvent::Kind::report && event.report.state == state) {
                    return true;
                }
            }
            return false;
        });
    }

    // Delivers a control as the SCM does: the handler runs on the caller's
    // thread. What the handler answered.
    unsigned long control(rp::ServiceControl control) const
    {
        rp::ServiceControlHandler handler;
        {
            const std::lock_guard<std::mutex> lock{mutex_};
            handler = handler_;
        }
        return handler(control);
    }

    // Lets the handler go, and with it what it holds of the service.
    void forget()
    {
        context = nullptr;
        const std::lock_guard<std::mutex> lock{mutex_};
        handler_ = nullptr;
    }

private:
    void add(HostEvent event)
    {
        {
            const std::lock_guard<std::mutex> lock{mutex_};
            events_.push_back(std::move(event));
        }
        changed_.notify_all();
    }

    mutable std::mutex mutex_;
    mutable std::condition_variable changed_;
    std::vector<HostEvent> events_;
    rp::ServiceControlHandler handler_;
};

// A valid config (the lab's tenant and restore targets) with `log_level`.
inline std::string config_json(std::string_view log_level = "info")
{
    const graph_lab::Lab_values& v = graph_lab::lab_values();
    return nlohmann::json{
        {"cloud_url", "https://cloud.example.invalid"},
        {"veeam_url", "https://veeam.test:4443"},
        {"veeam_org_name", "RestoreProofLab.onmicrosoft.com"},
        {"graph_tenant_id", graph_lab::kTenant},
        {"graph_client_id", graph_lab::kClient},
        {"test_mailbox", v.mailbox},
        {"test_site_id", v.site_id},
        {"test_library_id", v.library_id},
        {"test_onedrive_drive_id", v.onedrive_drive_id},
        {"test_onedrive_folder_id", v.folder_id},
        {"log_level", std::string{log_level}},
    }
        .dump(2);
}

inline std::string utf8_of(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

// What the body's thread saw, kept for the test's thread to assert on.
struct BodySeen {
    std::atomic<int> calls{0};
    std::atomic<bool> stop_requested_at_start{false};
    std::atomic<bool> had_logger{false};
    std::mutex mutex;
    std::string log_level;
    std::filesystem::path config_path;
    std::weak_ptr<rp::ServiceContext> context;
};

// A service on the fake host, with its log in <temp>\logs and its config in
// <temp>\config.json. The members are declared so that the temp folder goes
// last, when the service has let its log file go.
struct Lab {
    TempDir tmp;
    FakeHost fake;
    std::filesystem::path log_dir = tmp.path() / "logs";
    std::filesystem::path config_file;
    rp::ServiceOptions options;
    BodySeen seen;
    // What a test's body or seam waits for, opened by the test or, at the
    // latest, by the Lab's end.
    rp::StopSignal release;
    // Set when the body has started and handed over its context.
    rp::StopSignal body_started;

    explicit Lab(std::string_view log_level = "info")
    {
        config_file = tmp.write("config.json", config_json(log_level));
        options.host = fake.host();
        options.config_path = config_file;
        options.default_log_dir = [this] { return log_dir; };
        // Never the machine's own, whatever a test leaves unset.
        options.default_config_path = [this] { return config_file; };
    }

    ~Lab()
    {
        release.request();
        if (runner_.joinable()) {
            if (fake.has_handler()) {
                fake.control(rp::ServiceControl::stop);
            }
            runner_.join();
        }
        fake.forget();
        gone();
    }

    Lab(const Lab&) = delete;
    Lab& operator=(const Lab&) = delete;

    // A body that hands the fake its context and notes what it was given,
    // then does `then`.
    rp::ServiceBody body(std::function<void(rp::ServiceContext&)> then)
    {
        return [this, then = std::move(then)](const std::shared_ptr<rp::ServiceContext>& context) {
            ++seen.calls;
            seen.stop_requested_at_start = context->stop.requested();
            seen.had_logger = context->logger != nullptr;
            {
                const std::lock_guard<std::mutex> lock{seen.mutex};
                seen.log_level = context->config.log_level;
                seen.config_path = context->config_path;
                seen.context = context;
            }
            fake.context = context.get();
            body_started.request();
            then(*context);
        };
    }

    // Service::run on a thread of its own.
    void start()
    {
        runner_ = std::thread{[this] { result_ = rp::Service{options}.run(); }};
    }

    // Waits for Service::run to return; what it returned.
    rp::ServiceRun finish()
    {
        runner_.join();
        fake.forget();
        return result_;
    }

    rp::ServiceRun run()
    {
        start();
        return finish();
    }

    // Waits until nothing holds the service's context any more: the body's
    // thread has ended, detached or not. False when it still lives. True at
    // once for a service whose body never ran.
    bool gone()
    {
        std::weak_ptr<rp::ServiceContext> context;
        {
            const std::lock_guard<std::mutex> lock{seen.mutex};
            context = seen.context;
        }
        const auto deadline = std::chrono::steady_clock::now() + kPatience;
        while (!context.expired()) {
            if (std::chrono::steady_clock::now() > deadline) {
                return false;
            }
            std::this_thread::yield();
        }
        return true;
    }

    std::filesystem::path log_file() const { return log_dir / rp::kLogFileName; }

    // The log's bytes; empty when there is no file.
    std::string log_text() const
    {
        std::ifstream stream(log_file(), std::ios::binary);
        std::ostringstream out;
        out << stream.rdbuf();
        return out.str();
    }

    // The log's lines without their time: "<level> <message>". A line that
    // doesn't start with a time of the log's form is kept whole, so a test
    // that compares lines fails on it.
    std::vector<std::string> log_lines() const
    {
        // "2026-10-08T12:00:00.123Z ": 25 characters.
        constexpr std::size_t kTime = 25;
        std::vector<std::string> lines;
        const std::string text = log_text();
        std::string_view rest{text};
        while (!rest.empty()) {
            const std::size_t end = rest.find("\r\n");
            std::string_view line = rest.substr(0, end);
            rest.remove_prefix(end == std::string_view::npos ? rest.size() : end + 2);
            if (line.size() > kTime && line[10] == 'T' && line[23] == 'Z' && line[24] == ' ') {
                line.remove_prefix(kTime);
            }
            lines.emplace_back(line);
        }
        return lines;
    }

    // Whether nothing holds the log file open: Windows deletes a file only
    // then. The file is gone afterwards.
    bool log_file_is_closed() const
    {
        std::error_code ec;
        return std::filesystem::remove(log_file(), ec) && !ec;
    }

private:
    std::thread runner_;
    rp::ServiceRun result_;
};

} // namespace rp::test::service_lab
