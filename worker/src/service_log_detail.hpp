#pragma once

// Internal to rpcore: the one conversion the service's log makes
// (service_log.cpp), exposed so tests can ask it about paths no test may
// create, and the log's file sink, exposed so tests can refuse its renames.

#include <rp/service_log.hpp>

#include <spdlog/sinks/sink.h>

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace rp::detail {

// `path` in the machine's ANSI code page, which is how spdlog as built takes
// a file name (the narrow CRT calls; SPDLOG_WCHAR_FILENAMES is off), or
// nullopt when the code page doesn't give the same path back: a letter it
// lacks, which Windows would otherwise replace by '?' or by a letter that
// looks like it (best fit), and the log would open in another folder.
std::optional<std::string> ansi_path(const std::filesystem::path& path);

// Renames `from` to `to`, in place of a file that is there; false when it
// couldn't be done, and then nothing changed. The log's one rename, a seam so
// tests can refuse it where no reader can be made to.
using RenameLogFile =
    std::function<bool(const std::filesystem::path& from, const std::filesystem::path& to)>;

// The real one: one MoveFileExW that replaces. Windows refuses it while
// somebody holds either file open without sharing its deletion.
bool rename_log_file(const std::filesystem::path& from, const std::filesystem::path& to) noexcept;

// The file under ServiceLogSink: `file`, opened for appending under its name
// `narrow` (ansi_path), rotating by `limits`. Null when the limits hold no
// line (max_bytes 0); throws spdlog::spdlog_ex when the file can't be opened.
// Single-threaded: ServiceLogSink's lock is the one lock.
//
// Our own and not spdlog's rotating sink, which answers a rename that fails
// by emptying the live file and dropping the line it was writing (W4.7 code
// review). Here a line that would take worker.log past max_bytes first moves
// the files one number up, the oldest first and worker.log last, as far up
// as the first number no file has; only when every number is taken is the
// oldest file replaced by the one below it, which is the rotation's one
// intended loss. It stops at the first rename that fails: no file is then
// put over one that wasn't moved, nothing is emptied, the line is appended to
// worker.log as it is, and the next line tries again, ending at the number
// the failed try left free and so replacing nothing. No line on disk is lost
// to a rotation that can't be made; worker.log is over its limit for as long
// as that lasts, and such a line is no write failure. With no old file to
// keep (limits.files of 0 or 1) worker.log is emptied when it is full, as
// its limits say. A worker.log that can't be opened again after a rotation
// fails that line, and every line after it (each counted) until it opens,
// which every line tries.
std::shared_ptr<spdlog::sinks::sink> make_log_file_sink(const std::filesystem::path& file,
                                                        const std::string& narrow,
                                                        LogLimits limits,
                                                        RenameLogFile rename = rename_log_file);

} // namespace rp::detail
