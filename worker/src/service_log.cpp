#include <rp/service_log.hpp>

#include <rp/config.hpp>
#include <rp/redact.hpp>

#include "folder_ops.hpp"
#include "service_log_detail.hpp"
#include "text_util.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <spdlog/details/log_msg.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <algorithm>
#include <array>
#include <utility>

namespace rp {

namespace {

using Level = spdlog::level::level_enum;

// One line: "2026-10-08T12:00:00.123Z info message", in UTC, the level in
// spdlog's words, ended by CR LF.
constexpr const char* kLinePattern = "%Y-%m-%dT%H:%M:%S.%eZ %l %v";
constexpr const char* kLineEnd = "\r\n";

// The seven words of the config key `log_level` (config.cpp's kLogLevels).
struct LevelWord {
    std::string_view word;
    Level level;
};

constexpr std::array<LevelWord, 7> kLevelWords{{
    {"trace", Level::trace},
    {"debug", Level::debug},
    {"info", Level::info},
    {"warn", Level::warn},
    {"error", Level::err},
    {"critical", Level::critical},
    {"off", Level::off},
}};

} // namespace

namespace detail {

std::optional<std::string> ansi_path(const std::filesystem::path& path)
{
    const std::wstring& wide = path.native();
    // No best fit: a letter the code page lacks must not come back as one
    // that looks like it. A UTF-8 code page takes no such flag and needs
    // none.
    const DWORD flags = GetACP() == CP_UTF8 ? 0 : WC_NO_BEST_FIT_CHARS;
    // At most four bytes a UTF-16 unit, in any code page.
    std::string narrow(wide.size() * 4 + 1, '\0');
    narrow.resize(static_cast<std::size_t>(
        std::max(0, WideCharToMultiByte(CP_ACP, flags, wide.data(), static_cast<int>(wide.size()),
                                        narrow.data(), static_cast<int>(narrow.size()), nullptr,
                                        nullptr))));
    // And back: what the narrow calls will open. A letter that was replaced
    // (by '?', the default character) doesn't come back as itself.
    std::wstring back(wide.size() + 1, L'\0');
    back.resize(static_cast<std::size_t>(
        std::max(0, MultiByteToWideChar(CP_ACP, 0, narrow.data(), static_cast<int>(narrow.size()),
                                        back.data(), static_cast<int>(back.size())))));
    return back == wide ? std::optional<std::string>{std::move(narrow)} : std::nullopt;
}

} // namespace detail

std::filesystem::path default_log_dir()
{
    return program_data_dir() / "RestoreProof" / "logs";
}

std::optional<spdlog::level::level_enum> log_level_of(std::string_view word) noexcept
{
    const auto found = std::find_if(kLevelWords.begin(), kLevelWords.end(),
                                    [word](const LevelWord& row) { return row.word == word; });
    return found != kLevelWords.end() ? std::optional<Level>{found->level} : std::nullopt;
}

// --- ServiceLogSink ---------------------------------------------------------

ServiceLogSink::ServiceLogSink(std::shared_ptr<spdlog::sinks::sink> inner,
                               spdlog::level::level_enum level)
    : threshold_(static_cast<int>(level)), inner_(std::move(inner))
{
    inner_->set_formatter(std::make_unique<spdlog::pattern_formatter>(
        kLinePattern, spdlog::pattern_time_type::utc, kLineEnd));
}

void ServiceLogSink::log(const spdlog::details::log_msg& msg)
{
    const std::string_view message{msg.payload.data(), msg.payload.size()};
    // Decided on the message as it came: redaction never touches the prefix,
    // and a line that isn't written costs no redaction.
    if (!writes(msg.level, message)) {
        return;
    }
    // Redacted first, while the message still has the line ends some of
    // redact's rules read; then no line end is left.
    const std::string line = without_controls(redact(message));
    spdlog::details::log_msg clean = msg;
    clean.payload = line;
    const std::lock_guard<std::mutex> lock{mutex_};
    if (inner_) {
        inner_->log(clean);
        // Every line is on disk when it is written: a kill loses none.
        inner_->flush();
    }
}

void ServiceLogSink::flush()
{
    const std::lock_guard<std::mutex> lock{mutex_};
    if (inner_) {
        inner_->flush();
    }
}

void ServiceLogSink::set_pattern(const std::string&) {}

void ServiceLogSink::set_formatter(std::unique_ptr<spdlog::formatter>) {}

void ServiceLogSink::set_threshold(spdlog::level::level_enum level) noexcept
{
    threshold_.store(static_cast<int>(level));
}

spdlog::level::level_enum ServiceLogSink::threshold() const noexcept
{
    return static_cast<Level>(threshold_.load());
}

bool ServiceLogSink::writes(spdlog::level::level_enum level, std::string_view message) const noexcept
{
    return static_cast<int>(level) >= threshold_.load() || message.starts_with(kSecurityPrefix);
}

void ServiceLogSink::close()
{
    const std::lock_guard<std::mutex> lock{mutex_};
    inner_.reset();
}

// --- ServiceLog -------------------------------------------------------------

ServiceLog::ServiceLog(std::shared_ptr<spdlog::sinks::sink> inner, spdlog::level::level_enum level,
                       std::filesystem::path file)
    : failures_(std::make_shared<std::atomic<std::uint64_t>>(0)),
      sink_(std::make_shared<ServiceLogSink>(std::move(inner), level)),
      logger_(std::make_shared<spdlog::logger>(std::string{kServiceLoggerName}, sink_)),
      file_(std::move(file))
{
    // Counted and nothing else: spdlog's own handler would print the text on
    // stderr, which a service doesn't have, and the text may hold anything.
    logger_->set_error_handler([failures = failures_](const std::string&) { ++*failures; });
    set_level(level);
}

const std::shared_ptr<spdlog::logger>& ServiceLog::logger() const noexcept
{
    return logger_;
}

const std::filesystem::path& ServiceLog::file() const noexcept
{
    return file_;
}

void ServiceLog::set_level(spdlog::level::level_enum level)
{
    sink_->set_threshold(level);
    // `off` would stop a SECURITY line at the logger, before the sink's rule.
    logger_->set_level(level == Level::off ? Level::critical : level);
}

spdlog::level::level_enum ServiceLog::level() const noexcept
{
    return sink_->threshold();
}

std::uint64_t ServiceLog::write_failures() const noexcept
{
    return failures_->load();
}

void ServiceLog::flush()
{
    // Through the logger, whose catch hands a failure to the counter.
    logger_->flush();
}

void ServiceLog::close()
{
    flush();
    sink_->close();
}

std::variant<std::shared_ptr<ServiceLog>, ServiceLogFailure>
make_service_logger(const std::filesystem::path& folder, spdlog::level::level_enum level,
                    LogLimits limits)
{
    const std::filesystem::path file = folder / std::filesystem::path{kLogFileName};
    // Before anything is made: a folder made under a name spdlog would then
    // open another file for helps nobody.
    const std::optional<std::string> narrow = detail::ansi_path(file);
    if (!narrow) {
        return ServiceLogFailure::code_page;
    }
    if (!make_folder(folder)) {
        return ServiceLogFailure::folder;
    }
    // spdlog's count is of the old files beside the live one.
    const std::size_t old_files = limits.files > 0 ? limits.files - 1 : 0;
    std::shared_ptr<spdlog::sinks::sink> inner;
    try {
        // Single-threaded: ServiceLogSink's lock is the one lock.
        inner = std::make_shared<spdlog::sinks::rotating_file_sink_st>(*narrow, limits.max_bytes,
                                                                       old_files);
    } catch (const spdlog::spdlog_ex&) {
        // The file couldn't be opened; `inner` stays null.
    }
    if (!inner) {
        return ServiceLogFailure::file;
    }
    return std::make_shared<ServiceLog>(std::move(inner), level, file);
}

} // namespace rp
