#pragma once

// The service's log (W4.7, docs/decisions.md 2026-10-08 point 7):
// %ProgramData%\RestoreProof\logs\worker.log, written by the service alone. No
// command logs there; the commands' loggers stay on stderr.
//
// Three things hold for every line, by construction and not by its call site:
//  - it went through rp::redact, in the logger's one sink (ServiceLogSink), so
//    a call site that forgot is covered and a new one can't forget;
//  - it is one line: a control character in a message (a line break above
//    all) is written as a space, so no message forges a second line;
//  - it is written when its level is at or above `log_level`, or when its
//    message starts with "SECURITY: ", whatever `log_level` is. `off`
//    therefore means "the SECURITY lines only".
// A line is "<UTC time to the ms>Z <level> <message>", the level in spdlog's
// words (trace, debug, info, warning, error, critical), ended by CR LF, and it
// is on disk when the call that wrote it returns.
//
// The file rotates: worker.log is the live file, worker.1.log the newest old
// one. The rotation is the log's own (src/service_log_detail.hpp,
// make_log_file_sink): a rename Windows refuses, because somebody holds one of
// the files open, empties nothing and loses no line; worker.log then grows
// past its limit until the rotation can be made. The logger is handed on and
// never global: not registered with spdlog and not its default logger.
//
// Strict (100% line): this decides whether a SECURITY line is written and
// whether a line is redacted.

#include <spdlog/logger.h>
#include <spdlog/sinks/sink.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace rp {

// The log file's name inside its folder.
inline constexpr std::string_view kLogFileName = "worker.log";

// What a message starts with to be written under every `log_level`: the
// prefix rp::log_security gives every security line (and nothing else does).
inline constexpr std::string_view kSecurityPrefix = "SECURITY: ";

// The service logger's name. It is in no line and in no registry.
inline constexpr std::string_view kServiceLoggerName = "rpworker";

// program_data_dir() / "RestoreProof" / "logs". Throws what program_data_dir
// throws.
std::filesystem::path default_log_dir();

// How large the log grows: `max_bytes` a file, `files` files in all, the live
// one included (worker.log and worker.1.log to worker.4.log: 50 MiB at most).
// One file, or none, keeps worker.log alone, emptied when it is full. The
// limits hold while the rotation can be made; a file somebody holds open
// stops it, and worker.log is over max_bytes for as long.
struct LogLimits {
    std::size_t max_bytes = 10u * 1024u * 1024u;
    std::size_t files = 5;
};

// spdlog's level for one of the seven words the config key `log_level` may be
// (trace, debug, info, warn, error, critical, off; rp/config.hpp), exactly as
// written there; nullopt for anything else. Its own table: spdlog's parser
// takes other words and reads one it doesn't know as `off`.
std::optional<spdlog::level::level_enum> log_level_of(std::string_view word) noexcept;

// The logger's only sink. log() decides whether the line is written (the
// rule above, on the message as it came), passes the message through
// rp::redact, replaces each control character (src/control_chars.hpp) by a
// space, hands the result to the inner sink and flushes it. The inner sink is
// given the line's form when this sink is made, and set_pattern and
// set_formatter change nothing afterwards. Whatever the inner sink throws (a
// full disk) leaves log() and flush(): the logger's error handler counts it.
// Thread-safe: one lock around the inner sink, so that may be a
// single-threaded one.
class ServiceLogSink final : public spdlog::sinks::sink {
public:
    // `level` is the configured `log_level`, `off` included. The sink's own
    // spdlog level (sink::level()) stays at trace and is not this: a logger
    // asks it before log(), which would drop a SECURITY line.
    ServiceLogSink(std::shared_ptr<spdlog::sinks::sink> inner, spdlog::level::level_enum level);

    void log(const spdlog::details::log_msg& msg) override;
    void flush() override;
    // Both do nothing: the line's form is this file's.
    void set_pattern(const std::string& pattern) override;
    void set_formatter(std::unique_ptr<spdlog::formatter> formatter) override;

    // The configured level, and changing it (once the config is read).
    void set_threshold(spdlog::level::level_enum level) noexcept;
    spdlog::level::level_enum threshold() const noexcept;

    // The rule: `level` at or above threshold(), or `message` starting with
    // kSecurityPrefix.
    bool writes(spdlog::level::level_enum level, std::string_view message) const noexcept;

    // Lets the inner sink go (a file sink closes its file when nobody else
    // holds it). Lines logged afterwards are dropped, and flush() does
    // nothing. Doesn't flush: ServiceLog::close does, through the logger.
    void close();

private:
    std::atomic<int> threshold_;
    std::mutex mutex_;
    // Null once closed.
    std::shared_ptr<spdlog::sinks::sink> inner_;
};

// The service's log, open: its logger, and what the service does with the log
// besides writing lines. Held by shared_ptr; the logger may outlive it (the
// file is closed when the last holder of either goes, or by close()).
class ServiceLog {
public:
    // A log over any inner sink, `file` the path it writes to (empty when it
    // is no file). What make_service_logger does once worker.log is open;
    // tests hand it a sink of their own.
    ServiceLog(std::shared_ptr<spdlog::sinks::sink> inner, spdlog::level::level_enum level,
               std::filesystem::path file = {});

    // The logger, named kServiceLoggerName: one sink (a ServiceLogSink), not
    // registered with spdlog, never its default logger. Its level is the
    // configured one, or `critical` when that is `off`, so should_log()
    // guards go on saving their callers' work and a SECURITY line, which is
    // always critical, reaches the sink under every level. Never null.
    const std::shared_ptr<spdlog::logger>& logger() const noexcept;

    // The live log file; empty for a log over a sink that is no file.
    const std::filesystem::path& file() const noexcept;

    // The configured level (`off` included), and changing it: the service
    // opens its log at info and sets `log_level` once the config is read.
    void set_level(spdlog::level::level_enum level);
    spdlog::level::level_enum level() const noexcept;

    // How many lines or flushes failed since the log was opened: a write the
    // inner sink refused (a full disk, a worker.log that can't be opened
    // again after a rotation), anything thrown while a line was made (an
    // allocation failing in redact), a message spdlog couldn't format. Such
    // a line is not written, never written unredacted, and nothing else
    // changes: no line already in the log is lost, and the service doesn't
    // stop over its log. A rotation that can't be made is none of these: its
    // line is written.
    std::uint64_t write_failures() const noexcept;

    // Flushes the inner sink. Every line is flushed when it is written, so
    // this is for certainty before the process ends. Never throws; a failure
    // is counted.
    void flush();

    // Flushes, then lets the file go. What is logged afterwards goes nowhere
    // and counts as no failure. Calling it again does nothing.
    void close();

private:
    std::shared_ptr<std::atomic<std::uint64_t>> failures_;
    std::shared_ptr<ServiceLogSink> sink_;
    std::shared_ptr<spdlog::logger> logger_;
    std::filesystem::path file_;
};

// Why the log wasn't opened. To the service all three are "the log couldn't
// be opened" (its own code 2).
enum class ServiceLogFailure {
    // The path of worker.log doesn't survive the machine's ANSI code page,
    // which is how spdlog as built takes a file name: a letter the code page
    // lacks. Nothing was made.
    code_page,
    // `folder` isn't there and couldn't be made.
    folder,
    // worker.log couldn't be opened for appending there (or the limits hold
    // no line: max_bytes 0).
    file,
};

// Opens the service's log: makes `folder` and the levels above it that aren't
// there (the inherited ACL; an existing folder is left as it is), then opens
// folder / kLogFileName for appending, rotating by `limits`. Nothing is
// written by the opening. `level` is the configured `log_level` (`off`
// included). Never throws what the file system or spdlog throws.
std::variant<std::shared_ptr<ServiceLog>, ServiceLogFailure>
make_service_logger(const std::filesystem::path& folder, spdlog::level::level_enum level,
                    LogLimits limits = {});

} // namespace rp
