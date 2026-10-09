#pragma once

// The pipeline's two streams in the service (W4.8, docs/decisions.md
// 2026-10-08 point 12): rp::LogLineStream is an std::ostream that turns each
// completed line written to it into one log line "[<run_id>] <line>", the
// pipeline's stdout at info and its stderr at warning. The line then passes
// the service log's one sink, which redacts it and writes control characters
// as spaces (rp/service_log.hpp); nothing is redacted here.
//
//  - A line ends at LF; a CR right before it is dropped (CR LF).
//  - An empty line is skipped: the pipeline's blank lines set its paragraphs
//    apart on a console and say nothing in a log.
//  - A last line without its line break is written by finish(), which the
//    destructor calls: when the run ends.
//  - The stream never fails: every write is taken, and neither badbit nor
//    failbit is set by it, so "stdout was lost" can't happen in the service.
//    A line the writer threw on is lost and the next is written as ever; the
//    log's sink counts its own failures.
//
// Not thread-safe: one stream is written by one thread, the run's.
//
// Strict (100% line), by its name.

#include <spdlog/common.h>

#include <functional>
#include <memory>
#include <ostream>
#include <streambuf>
#include <string>
#include <string_view>

namespace spdlog {
class logger;
}

namespace rp {

// Where a finished line goes, the prefix already on it.
using LogLineWriter = std::function<void(std::string_view line)>;

// A writer that logs each line to `logger` at `level`, the line as text and
// never as a format string. Null `logger`: lines go nowhere.
LogLineWriter log_line_writer(std::shared_ptr<spdlog::logger> logger,
                              spdlog::level::level_enum level);

namespace detail {

// The stream's buffer: no put area, every character taken as it comes.
class LogLineBuffer final : public std::streambuf {
public:
    LogLineBuffer(LogLineWriter write, std::string_view run_id);

    // Writes what is left of a line that never got its break.
    void finish() noexcept;

protected:
    int_type overflow(int_type ch) override;
    std::streamsize xsputn(const char* text, std::streamsize count) override;

private:
    void take(std::string_view text) noexcept;
    void add(std::string_view piece, bool ended);

    LogLineWriter write_;
    std::string prefix_;
    std::string pending_;
};

// Holds the buffer so that it is made before the ostream that uses it.
struct LogLineBufferHolder {
    LogLineBufferHolder(LogLineWriter write, std::string_view run_id);
    LogLineBuffer buffer_;
};

} // namespace detail

class LogLineStream final : private detail::LogLineBufferHolder, public std::ostream {
public:
    // Lines go to `logger` at `level` as "[<run_id>] <line>".
    LogLineStream(std::shared_ptr<spdlog::logger> logger, spdlog::level::level_enum level,
                  std::string_view run_id);
    // Lines go to `write`; a null one takes nothing. What it throws is caught.
    LogLineStream(LogLineWriter write, std::string_view run_id);
    // finish().
    ~LogLineStream() override;

    LogLineStream(const LogLineStream&) = delete;
    LogLineStream& operator=(const LogLineStream&) = delete;

    // Writes a last line that never got its line break, if there is one.
    // The stream can be written to afterwards. Never throws.
    void finish() noexcept;
};

} // namespace rp
