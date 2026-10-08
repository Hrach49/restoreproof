// W4.7: the service's log (rp/service_log.hpp, docs/decisions.md 2026-10-08
// point 7). Every test logs into a folder of its own under the temp directory,
// never %ProgramData%. What is asserted is what the file holds, read while the
// log is still open: a line is on disk when the call that wrote it returns.
// Failure paths first: a log that can't be opened, a line that must not be
// written as it came, a write that fails.

#include <rp/config.hpp>
#include <rp/redact.hpp>
#include <rp/service_log.hpp>

#include "../src/service_log_detail.hpp"
#include "../src/target_guard_refuse.hpp"
#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <spdlog/details/log_msg.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::EndsWith;
using Catch::Matchers::StartsWith;
using rp::test::TempDir;
using Level = spdlog::level::level_enum;

namespace {

constexpr std::size_t kKiB = 1024;

// A file's bytes; empty when it can't be opened.
std::string bytes_of(const std::filesystem::path& file)
{
    std::ifstream stream(file, std::ios::binary);
    std::ostringstream out;
    out << stream.rdbuf();
    return out.str();
}

// `text` cut at each CRLF. Text after the last one, a line that was never
// ended, is a line of its own, so a test that counts lines sees it.
std::vector<std::string> lines_of(std::string_view text)
{
    std::vector<std::string> lines;
    while (!text.empty()) {
        const std::size_t end = text.find("\r\n");
        lines.emplace_back(text.substr(0, end));
        text.remove_prefix(end == std::string_view::npos ? text.size() : end + 2);
    }
    return lines;
}

// The lines of the live log file.
std::vector<std::string> log_lines(const std::filesystem::path& folder)
{
    return lines_of(bytes_of(folder / rp::kLogFileName));
}

// A line without its time: "<level> <message>". The time's form is checked
// here, on every line any test reads.
std::string after_time(const std::string& line)
{
    static const std::regex form{R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z (.*)$)"};
    std::smatch match;
    INFO("line: " << line);
    REQUIRE(std::regex_match(line, match, form));
    return match[1].str();
}

std::vector<std::string> log_lines_after_time(const std::filesystem::path& folder)
{
    std::vector<std::string> out;
    for (const std::string& line : log_lines(folder)) {
        out.push_back(after_time(line));
    }
    return out;
}

std::vector<std::string> lines_after_time(const std::filesystem::path& file)
{
    std::vector<std::string> out;
    for (const std::string& line : lines_of(bytes_of(file))) {
        out.push_back(after_time(line));
    }
    return out;
}

// Every line of the log's files in `folder`, the oldest file first.
std::vector<std::string> all_lines_oldest_first(const std::filesystem::path& folder)
{
    std::vector<std::string> out;
    for (const char* name :
         {"worker.4.log", "worker.3.log", "worker.2.log", "worker.1.log", "worker.log"}) {
        for (std::string& line : lines_after_time(folder / name)) {
            out.push_back(std::move(line));
        }
    }
    return out;
}

// A reader that holds a file open the way a CRT or .NET one does: others may
// read and write it, nobody may rename it, replace it or delete it.
class HeldOpen {
public:
    explicit HeldOpen(const std::filesystem::path& file)
        : handle_(CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr))
    {
        REQUIRE(handle_ != INVALID_HANDLE_VALUE);
    }

    ~HeldOpen() { release(); }

    HeldOpen(const HeldOpen&) = delete;
    HeldOpen& operator=(const HeldOpen&) = delete;

    void release()
    {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

private:
    HANDLE handle_;
};

// Writes numbered info lines of about 75 bytes through a log and keeps what
// each must read in the file, in order.
struct LineWriter {
    std::shared_ptr<rp::ServiceLog> log;
    std::string what;
    std::vector<std::string> written{};

    void write(int count)
    {
        for (int i = 0; i < count; ++i) {
            const std::string digits = std::to_string(written.size());
            const std::string message =
                "line " + std::string(3 - digits.size(), '0') + digits + " of " + what;
            log->logger()->info(message);
            written.push_back("info " + message);
        }
    }
};

// The log, opened in `folder`; the test fails when it isn't.
std::shared_ptr<rp::ServiceLog> open_log(const std::filesystem::path& folder, Level level,
                                         rp::LogLimits limits = {})
{
    auto made = rp::make_service_logger(folder, level, limits);
    REQUIRE(std::holds_alternative<std::shared_ptr<rp::ServiceLog>>(made));
    std::shared_ptr<rp::ServiceLog> log = std::get<std::shared_ptr<rp::ServiceLog>>(made);
    REQUIRE(log != nullptr);
    return log;
}

// What a refused make_service_logger said; the test fails when it opened.
rp::ServiceLogFailure failure_of(const std::filesystem::path& folder, rp::LogLimits limits = {})
{
    auto made = rp::make_service_logger(folder, Level::info, limits);
    REQUIRE(std::holds_alternative<rp::ServiceLogFailure>(made));
    return std::get<rp::ServiceLogFailure>(made);
}

// The names in a folder.
std::set<std::string> names_in(const std::filesystem::path& folder)
{
    std::set<std::string> names;
    for (const auto& entry : std::filesystem::directory_iterator(folder)) {
        names.insert(entry.path().filename().string());
    }
    return names;
}

// An inner sink that keeps what it is handed, as it was handed, and fails
// when told to.
class RecordingSink final : public spdlog::sinks::sink {
public:
    void log(const spdlog::details::log_msg& msg) override
    {
        handed.emplace_back(msg.payload.data(), msg.payload.size());
        if (fail_log) {
            throw std::runtime_error("the disk is full");
        }
        written.emplace_back(msg.payload.data(), msg.payload.size());
    }

    void flush() override
    {
        ++flushes;
        if (fail_flush) {
            throw std::runtime_error("the disk is full");
        }
    }

    void set_pattern(const std::string&) override { ++formatters; }
    void set_formatter(std::unique_ptr<spdlog::formatter>) override { ++formatters; }

    std::vector<std::string> handed;
    std::vector<std::string> written;
    int flushes = 0;
    int formatters = 0;
    bool fail_log = false;
    bool fail_flush = false;
};

// The seven words `log_level` may be (rp/config.hpp), with spdlog's level.
struct LevelRow {
    std::string_view word;
    Level level;
};

constexpr LevelRow kLevels[] = {
    {"trace", Level::trace}, {"debug", Level::debug},       {"info", Level::info},
    {"warn", Level::warn},   {"error", Level::err},         {"critical", Level::critical},
    {"off", Level::off},
};

// A folder name no ANSI code page holds: Han, Cyrillic, Hebrew and Thai at once.
const wchar_t* const kNoCodePageName = L"logs-\u4E2D\u0416\u05E2\u0E01";

} // namespace

// --- What can't be opened ---------------------------------------------------

TEST_CASE("the service log isn't opened in a folder that can't be made", "[service_log]")
{
    const TempDir tmp;
    tmp.write("blocker", "a file where a folder would have to be");

    CHECK(failure_of(tmp.path() / "blocker" / "logs") == rp::ServiceLogFailure::folder);
    CHECK(failure_of(tmp.path() / "blocker") == rp::ServiceLogFailure::folder);
    CHECK(names_in(tmp.path()) == std::set<std::string>{"blocker"});
}

TEST_CASE("the service log isn't opened when worker.log can't be", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    std::filesystem::create_directories(folder / rp::kLogFileName);

    CHECK(failure_of(folder) == rp::ServiceLogFailure::file);
    // Nothing was put beside it, and it is still the folder it was.
    CHECK(names_in(folder) == std::set<std::string>{"worker.log"});
    CHECK(std::filesystem::is_directory(folder / rp::kLogFileName));
}

TEST_CASE("the service log isn't opened with limits that hold no line", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";

    CHECK(failure_of(folder, rp::LogLimits{0, 5}) == rp::ServiceLogFailure::file);
}

TEST_CASE("the service log isn't opened in a folder the ANSI code page can't name",
          "[service_log]")
{
    if (GetACP() == CP_UTF8) {
        SKIP("this machine's ANSI code page is UTF-8, which names every folder");
    }
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / kNoCodePageName;

    CHECK(failure_of(folder) == rp::ServiceLogFailure::code_page);
    // Refused before anything is made: no folder under a name spdlog would
    // then have opened another file for.
    CHECK(names_in(tmp.path()).empty());
    CHECK_FALSE(rp::detail::ansi_path(folder / rp::kLogFileName).has_value());
}

TEST_CASE("a path goes to spdlog only when the ANSI code page gives it back unchanged",
          "[service_log]")
{
    SECTION("ASCII is itself in every code page")
    {
        const std::optional<std::string> narrow =
            rp::detail::ansi_path(LR"(C:\ProgramData\RestoreProof\logs\worker.log)");
        REQUIRE(narrow.has_value());
        CHECK(*narrow == R"(C:\ProgramData\RestoreProof\logs\worker.log)");
    }
    SECTION("no best-fit letter stands in for one the code page lacks")
    {
        if (GetACP() != 1252) {
            SKIP("the letters here are chosen for code page 1252");
        }
        // 1252 holds e-acute as one byte, and would write U+0100 (A with
        // macron) as a plain A if best fit were allowed: another folder.
        const std::optional<std::string> held = rp::detail::ansi_path(L"C:\\caf\u00E9\\worker.log");
        REQUIRE(held.has_value());
        CHECK(*held == "C:\\caf\xE9\\worker.log");
        CHECK_FALSE(rp::detail::ansi_path(L"C:\\\u0100\\worker.log").has_value());
    }
    SECTION("a lone surrogate is no path")
    {
        const std::wstring lone = std::wstring{L"C:\\x"} + static_cast<wchar_t>(0xD800) + L"\\w.log";
        CHECK_FALSE(rp::detail::ansi_path(lone).has_value());
    }
}

TEST_CASE("the service log opens in a folder with a letter the code page holds", "[service_log]")
{
    if (GetACP() != 1252) {
        SKIP("the letter here is chosen for code page 1252");
    }
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / L"caf\u00E9" / L"logs";

    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);
    log->logger()->info("written");

    // In the folder asked for, not in one a wrong conversion would have named.
    CHECK(log->file() == folder / rp::kLogFileName);
    CHECK(log_lines_after_time(folder) == std::vector<std::string>{"info written"});
    CHECK(names_in(tmp.path()).size() == 1);
}

// --- What must not be written as it came ------------------------------------

TEST_CASE("a secret logged through the raw logger is redacted in the file", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::trace);
    const std::string sentinel = "RP-SENTINEL-9f3c1a";

    // Call sites that didn't redact, at every level and in every way a
    // message is made.
    log->logger()->info("signing in with password=" + sentinel);
    log->logger()->info("sent {}", "Authorization: Bearer " + sentinel);
    log->logger()->debug(R"(body {{"refresh_token":"{}","keep":"this"}})", sentinel);
    log->logger()->trace("https://user:{}@veeam.example.invalid:4443/v8/x", sentinel);
    log->logger()->warn("pfx_base64: {}", sentinel);
    log->logger()->error("token {}", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0." + sentinel);
    log->logger()->critical("SECURITY: evidence: client_secret={}", sentinel);
    log->logger()->log(Level::info, "signing_key_base64={}", sentinel);

    const std::string text = bytes_of(folder / rp::kLogFileName);
    CHECK_THAT(text, !ContainsSubstring(sentinel));
    const std::vector<std::string> lines = log_lines_after_time(folder);
    REQUIRE(lines.size() == 8);
    for (const std::string& line : lines) {
        CAPTURE(line);
        CHECK_THAT(line, ContainsSubstring(std::string{rp::kRedacted}));
    }
    // What isn't a secret stays readable.
    CHECK(lines[0] == "info signing in with password=[REDACTED]");
    CHECK(lines[2] == R"(debug body {"refresh_token":"[REDACTED]","keep":"this"})");
    CHECK(lines[6] == "critical SECURITY: evidence: client_secret=[REDACTED]");
}

TEST_CASE("a line a call site redacted itself is written as it would be anyway", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);

    log->logger()->info(rp::redact("POST /v8/token password=hunter2 grant_type=password"));
    log->logger()->info("nothing secret: 30 of 30 item(s) verified");

    CHECK(log_lines_after_time(folder) ==
          std::vector<std::string>{"info POST /v8/token password=[REDACTED] grant_type=password",
                                   "info nothing secret: 30 of 30 item(s) verified"});
}

TEST_CASE("a message with a line break is one line of the log", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);

    // A server's text that tries to write a line of its own.
    log->logger()->info("Veeam said: failed\r\n2026-10-08T12:00:00.000Z critical SECURITY: forged");
    log->logger()->info("tab\there, bell\x07, NEL\xC2\x85, line separator\xE2\x80\xA8, "
                        "override\xE2\x80\xAE, DEL\x7F, end\n");
    log->logger()->info("\n");
    // What is no control character stays byte for byte.
    log->logger()->info("caf\xC3\xA9 \xE4\xB8\xAD \xF0\x9F\x99\x82");

    const std::vector<std::string> lines = log_lines_after_time(folder);
    REQUIRE(lines.size() == 4);
    CHECK(lines[0] ==
          "info Veeam said: failed  2026-10-08T12:00:00.000Z critical SECURITY: forged");
    CHECK(lines[1] == "info tab here, bell , NEL , line separator , override , DEL , end ");
    CHECK(lines[2] == "info  ");
    CHECK(lines[3] == "info caf\xC3\xA9 \xE4\xB8\xAD \xF0\x9F\x99\x82");
    // Not one CR or LF but each line's own end.
    const std::string text = bytes_of(folder / rp::kLogFileName);
    CHECK(std::count(text.begin(), text.end(), '\n') == 4);
    CHECK(std::count(text.begin(), text.end(), '\r') == 4);
}

TEST_CASE("a line break a secret's redaction leaves behind is still no second line",
          "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);

    // The header rule ends its value at the line break and keeps the break.
    log->logger()->info("Authorization: Basic dXNlcjpwYXNz\r\nHost: veeam.example.invalid");

    CHECK(log_lines_after_time(folder) ==
          std::vector<std::string>{"info Authorization: [REDACTED]  Host: veeam.example.invalid"});
}

// --- The level, and the SECURITY lines --------------------------------------

TEST_CASE("the seven words of log_level are the table's, and nothing else is a level",
          "[service_log]")
{
    for (const LevelRow& row : kLevels) {
        CAPTURE(row.word);
        CHECK(rp::log_level_of(row.word) == row.level);
    }
    // spdlog's own parser takes these, or reads a word it doesn't know as off.
    const std::string_view not_a_level = GENERATE(values<std::string_view>(
        {"", "warning", "err", "INFO", "Info", "info ", " info", "information", "none", "0", "n"}));
    CAPTURE(not_a_level);
    CHECK(rp::log_level_of(not_a_level) == std::nullopt);
}

TEST_CASE("log_level's words are the ones the config takes", "[service_log]")
{
    // Every word the table knows parses as a config's log_level, and the
    // table knows every word a config can hold: the service reads the level
    // from a config that loaded.
    const auto parses = [](std::string_view word) {
        const std::string text = R"({
            "cloud_url": "https://cloud.example.invalid",
            "veeam_url": "https://veeam.example.invalid:4443",
            "veeam_org_name": "example.onmicrosoft.com",
            "graph_tenant_id": "00000000-0000-0000-0000-000000000001",
            "graph_client_id": "00000000-0000-0000-0000-000000000002",
            "test_mailbox": "restoretest@example.onmicrosoft.com",
            "test_site_id": "example.sharepoint.com,00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002",
            "test_library_id": "b!library-id",
            "test_onedrive_drive_id": "b!drive-id",
            "test_onedrive_folder_id": "folder-id",
            "log_level": ")" + std::string{word} + R"("})";
        bool parsed = false;
        try {
            parsed = rp::parse_config(text).log_level == word;
        } catch (const rp::ConfigError&) {
        }
        return parsed;
    };
    for (const LevelRow& row : kLevels) {
        CAPTURE(row.word);
        CHECK(parses(row.word));
    }
    for (const std::string_view word : {"warning", "err", "INFO", "none"}) {
        CAPTURE(word);
        CHECK_FALSE(parses(word));
        CHECK(rp::log_level_of(word) == std::nullopt);
    }
    // And the default, the level of a config that doesn't say.
    CHECK(rp::log_level_of(rp::Config{}.log_level) == Level::info);
}

TEST_CASE("a line is written at or above log_level, and a SECURITY line whatever it is",
          "[service_log]")
{
    const LevelRow row = GENERATE(from_range(std::begin(kLevels), std::end(kLevels)));
    CAPTURE(row.word);
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, row.level);
    const std::shared_ptr<spdlog::logger> logger = log->logger();

    logger->trace("a trace line");
    logger->debug("a debug line");
    logger->info("an info line");
    logger->warn("a warn line");
    logger->error("an error line");
    logger->critical("a critical line without the prefix");
    // The one emitter of a SECURITY line, as the guard and the Cleaner call it.
    rp::log_security(logger, "target guard: refused; nothing was restored");

    std::vector<std::string> expected;
    const std::pair<Level, std::string_view> lines[] = {
        {Level::trace, "trace a trace line"},
        {Level::debug, "debug a debug line"},
        {Level::info, "info an info line"},
        {Level::warn, "warning a warn line"},
        {Level::err, "error an error line"},
        {Level::critical, "critical a critical line without the prefix"},
    };
    for (const auto& [level, line] : lines) {
        if (level >= row.level) {
            expected.emplace_back(line);
        }
    }
    expected.emplace_back("critical SECURITY: target guard: refused; nothing was restored");
    CHECK(log_lines_after_time(folder) == expected);
    CHECK(log->level() == row.level);
    CHECK(log->write_failures() == 0);

    // The HTTP layer's guards go on saving their work: the logger itself says
    // what it would take, and never says no to a critical line.
    CHECK(logger->should_log(Level::critical));
    CHECK(logger->should_log(Level::debug) == (row.level <= Level::debug));
    CHECK(logger->should_log(Level::err) == (row.level <= Level::err));
}

TEST_CASE("the SECURITY rule is on the prefix at the message's start, exactly", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::off);

    log->logger()->critical("SECURITY: cleanup: refused");
    log->logger()->critical("SECURITY: ");
    log->logger()->critical("security: lower case");
    log->logger()->critical("SECURITY:no blank");
    log->logger()->critical(" SECURITY: after a blank");
    log->logger()->critical("see SECURITY: in the middle");
    log->logger()->critical("SECURITY");
    log->logger()->critical("");

    CHECK(log_lines_after_time(folder) ==
          std::vector<std::string>{"critical SECURITY: cleanup: refused", "critical SECURITY: "});
}

TEST_CASE("the sink writes a SECURITY line of any level; the level only decides the others",
          "[service_log]")
{
    // The rule itself, without a logger in front of it: should a line that
    // isn't critical ever carry the prefix, the sink still writes it.
    const auto inner = std::make_shared<RecordingSink>();
    rp::ServiceLogSink sink{inner, Level::off};

    CHECK(sink.writes(Level::info, "SECURITY: x"));
    CHECK(sink.writes(Level::trace, "SECURITY: "));
    CHECK_FALSE(sink.writes(Level::critical, "x"));
    CHECK_FALSE(sink.writes(Level::critical, "SECURITY:"));
    CHECK(sink.threshold() == Level::off);

    sink.set_threshold(Level::warn);
    CHECK(sink.threshold() == Level::warn);
    CHECK(sink.writes(Level::warn, "x"));
    CHECK(sink.writes(Level::critical, "x"));
    CHECK_FALSE(sink.writes(Level::info, "x"));
    CHECK(sink.writes(Level::info, "SECURITY: x"));

    sink.log(spdlog::details::log_msg{"rpworker", Level::info, "SECURITY: at info"});
    sink.log(spdlog::details::log_msg{"rpworker", Level::info, "dropped"});
    sink.log(spdlog::details::log_msg{"rpworker", Level::err, "kept password=x"});
    CHECK(inner->written ==
          std::vector<std::string>{"SECURITY: at info", "kept password=[REDACTED]"});
    // The sink's own spdlog level stays open: the logger asks it before log().
    CHECK(sink.should_log(Level::trace));
}

TEST_CASE("the level is changed once the config is read", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);
    const std::shared_ptr<spdlog::logger> logger = log->logger();

    logger->debug("debug at info");
    logger->info("info at info");

    log->set_level(Level::debug);
    CHECK(log->level() == Level::debug);
    CHECK(logger->should_log(Level::debug));
    logger->debug("debug at debug");

    log->set_level(Level::off);
    CHECK(log->level() == Level::off);
    CHECK_FALSE(logger->should_log(Level::err));
    CHECK(logger->should_log(Level::critical));
    logger->error("error at off");
    logger->critical("critical at off");
    rp::log_security(logger, "at off");

    log->set_level(Level::err);
    logger->warn("warn at error");
    logger->error("error at error");

    CHECK(log_lines_after_time(folder) ==
          std::vector<std::string>{"info info at info", "debug debug at debug",
                                   "critical SECURITY: at off", "error error at error"});
}

// --- The line ---------------------------------------------------------------

TEST_CASE("a line is the UTC time to the millisecond, the level and the message", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::trace);
    using namespace std::chrono;
    const spdlog::log_clock::time_point noon = time_point_cast<spdlog::log_clock::duration>(
        sys_days{year{2026} / 10 / 8} + 12h + 123ms);
    const spdlog::log_clock::time_point new_year = time_point_cast<spdlog::log_clock::duration>(
        sys_days{year{2027} / 1 / 1} + 5ms);
    const auto line_at = [&log](spdlog::log_clock::time_point time, Level level,
                                std::string_view message) {
        log->logger()->sinks().front()->log(
            spdlog::details::log_msg{time, spdlog::source_loc{}, "rpworker", level, message});
    };

    line_at(noon, Level::info, "service running: rpworker 0.0.0");
    line_at(noon, Level::warn, "a warning");
    line_at(noon, Level::err, "an error");
    line_at(noon, Level::critical, "SECURITY: x");
    line_at(noon, Level::debug, "d");
    line_at(noon, Level::trace, "t");
    // Midnight UTC, which no time zone but UTC writes as this date.
    line_at(new_year, Level::info, "midnight");

    CHECK(bytes_of(folder / rp::kLogFileName) ==
          "2026-10-08T12:00:00.123Z info service running: rpworker 0.0.0\r\n"
          "2026-10-08T12:00:00.123Z warning a warning\r\n"
          "2026-10-08T12:00:00.123Z error an error\r\n"
          "2026-10-08T12:00:00.123Z critical SECURITY: x\r\n"
          "2026-10-08T12:00:00.123Z debug d\r\n"
          "2026-10-08T12:00:00.123Z trace t\r\n"
          "2027-01-01T00:00:00.005Z info midnight\r\n");
}

TEST_CASE("nobody changes the line's form through the logger", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);

    log->logger()->set_pattern("%v");
    log->logger()->set_formatter(std::make_unique<spdlog::pattern_formatter>("FORGED %v"));
    log->logger()->sinks().front()->set_pattern("%v");
    log->logger()->info("still in form");

    CHECK(log_lines_after_time(folder) == std::vector<std::string>{"info still in form"});
}

TEST_CASE("the sink gives its inner sink the line's form once and no other", "[service_log]")
{
    std::ostringstream out;
    const auto inner = std::make_shared<spdlog::sinks::ostream_sink_st>(out);
    rp::ServiceLog log{inner, Level::info};

    log.logger()->info("through any inner sink");

    CHECK(lines_of(out.str()).size() == 1);
    CHECK(after_time(lines_of(out.str()).front()) == "info through any inner sink");
    CHECK_THAT(out.str(), EndsWith("\r\n"));
    // A log over a sink of the caller's has no file.
    CHECK(log.file().empty());

    const auto recording = std::make_shared<RecordingSink>();
    rp::ServiceLogSink sink{recording, Level::info};
    CHECK(recording->formatters == 1);
    sink.set_pattern("%v");
    sink.set_formatter(std::make_unique<spdlog::pattern_formatter>("%v"));
    CHECK(recording->formatters == 1);
}

// --- The file ---------------------------------------------------------------

TEST_CASE("the service log makes its folder and opens worker.log in it", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "RestoreProof" / "logs";

    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);

    CHECK(rp::kLogFileName == "worker.log");
    CHECK(log->file() == folder / "worker.log");
    CHECK(std::filesystem::is_regular_file(folder / "worker.log"));
    CHECK(names_in(folder) == std::set<std::string>{"worker.log"});
    // Nothing is written by the opening itself.
    CHECK(std::filesystem::file_size(folder / "worker.log") == 0);
    CHECK(log->level() == Level::info);
    CHECK(log->write_failures() == 0);
}

TEST_CASE("the default log folder is ProgramData's RestoreProof\\logs and the limits are "
          "10 MiB and five files",
          "[service_log]")
{
    CHECK(rp::default_log_dir() == rp::program_data_dir() / "RestoreProof" / "logs");
    CHECK(rp::default_log_dir().parent_path() == rp::default_config_path().parent_path());

    const rp::LogLimits limits;
    CHECK(limits.max_bytes == 10u * 1024u * 1024u);
    CHECK(limits.files == 5);
}

TEST_CASE("every line is in the file when the call that wrote it returns", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::trace);

    // The lowest level too: a kill loses none, whatever its level.
    log->logger()->trace("one");
    CHECK(log_lines_after_time(folder) == std::vector<std::string>{"trace one"});
    log->logger()->info("two");
    CHECK(log_lines_after_time(folder) == std::vector<std::string>{"trace one", "info two"});
}

TEST_CASE("a log that is opened again goes on where the file ended", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    {
        const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);
        log->logger()->info("the first start");
    }
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);
    log->logger()->info("the second start");

    CHECK(log_lines_after_time(folder) ==
          std::vector<std::string>{"info the first start", "info the second start"});
    CHECK(names_in(folder) == std::set<std::string>{"worker.log"});
}

TEST_CASE("rotation at a 1 KiB limit leaves five files and not six", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info, {kKiB, 5});

    // 200 lines of about 60 bytes: twelve files' worth.
    for (int i = 0; i < 200; ++i) {
        log->logger()->info("line {:03} of the rotation test, long enough", i);
    }

    CHECK(names_in(folder) == std::set<std::string>{"worker.log", "worker.1.log", "worker.2.log",
                                                    "worker.3.log", "worker.4.log"});
    CHECK(log->write_failures() == 0);
    // No file is over the limit, the newest lines are in worker.log, and the
    // files go back in time in the order of their numbers with no line lost
    // between them.
    std::vector<std::string> newest_first_files = {"worker.4.log", "worker.3.log", "worker.2.log",
                                                   "worker.1.log", "worker.log"};
    std::vector<std::string> all;
    for (const std::string& name : newest_first_files) {
        CAPTURE(name);
        CHECK(std::filesystem::file_size(folder / name) <= kKiB);
        CHECK(std::filesystem::file_size(folder / name) > 0);
        for (const std::string& line : lines_of(bytes_of(folder / name))) {
            all.push_back(after_time(line));
        }
    }
    REQUIRE(all.size() > 5);
    CHECK(all.back() == "info line 199 of the rotation test, long enough");
    for (std::size_t i = 0; i < all.size(); ++i) {
        const int number = 200 - static_cast<int>(all.size()) + static_cast<int>(i);
        const std::string digits = std::to_string(number);
        CHECK(all[i] == "info line " + std::string(3 - digits.size(), '0') + digits +
                            " of the rotation test, long enough");
    }
}

TEST_CASE("a file that is full when the log is opened is rotated by the first line",
          "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    std::filesystem::create_directories(folder);
    const std::string filler(kKiB - 10, 'x');
    {
        std::ofstream stream(folder / rp::kLogFileName, std::ios::binary);
        stream << filler;
    }
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info, {kKiB, 5});

    log->logger()->info("the first line after the start");

    CHECK(names_in(folder) == std::set<std::string>{"worker.log", "worker.1.log"});
    CHECK(bytes_of(folder / "worker.1.log") == filler);
    CHECK(log_lines_after_time(folder) ==
          std::vector<std::string>{"info the first line after the start"});
}

TEST_CASE("limits of one file, or of none, keep worker.log alone", "[service_log]")
{
    const std::size_t files = GENERATE(std::size_t{0}, std::size_t{1});
    CAPTURE(files);
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info, {kKiB, files});

    for (int i = 0; i < 60; ++i) {
        log->logger()->info("line {:03} of the one-file test, long enough", i);
    }

    CHECK(names_in(folder) == std::set<std::string>{"worker.log"});
    CHECK(std::filesystem::file_size(folder / "worker.log") <= kKiB);
    CHECK_THAT(log_lines_after_time(folder).back(), StartsWith("info line 059"));
    CHECK(log->write_failures() == 0);
}

// --- A rotation that can't be made ------------------------------------------
//
// Windows refuses to rename a file somebody holds open without sharing its
// deletion (a CRT or .NET reader tailing the log, a copy or a hash under
// way). A rotation that meets one changes nothing it can't finish: no file is
// emptied, the line being written is written, and worker.log grows past its
// limit until the rotation can be made.

TEST_CASE("a rotation a reader of worker.log blocks loses no line", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info, {kKiB, 5});
    LineWriter lines{log, "the blocked rotation"};

    rp::log_security(log->logger(), "kept through a blocked rotation");
    lines.written.emplace_back("critical SECURITY: kept through a blocked rotation");
    lines.write(10);
    REQUIRE(names_in(folder) == std::set<std::string>{"worker.log"});
    REQUIRE(std::filesystem::file_size(folder / "worker.log") < kKiB);

    HeldOpen reader{folder / "worker.log"};
    // Two files' worth, the SECURITY line and the line that crosses the
    // limit among them.
    lines.write(30);

    CHECK(names_in(folder) == std::set<std::string>{"worker.log"});
    CHECK(log_lines_after_time(folder) == lines.written);
    CHECK(std::filesystem::file_size(folder / "worker.log") > 2 * kKiB);
    // Every line was written: none failed.
    CHECK(log->write_failures() == 0);

    // The reader gone, the next line rotates what was waiting.
    reader.release();
    const std::vector<std::string> before = lines.written;
    lines.write(1);

    CHECK(names_in(folder) == std::set<std::string>{"worker.log", "worker.1.log"});
    CHECK(lines_after_time(folder / "worker.1.log") == before);
    CHECK(log_lines_after_time(folder) == std::vector<std::string>{lines.written.back()});
    CHECK(log->write_failures() == 0);
}

TEST_CASE("a rotation a reader of an old file blocks loses no line and moves no other file",
          "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info, {kKiB, 5});
    LineWriter lines{log, "the old file's reader"};

    for (int i = 0; i < 100 && !std::filesystem::exists(folder / "worker.2.log"); ++i) {
        lines.write(1);
    }
    const std::set<std::string> three{"worker.log", "worker.1.log", "worker.2.log"};
    REQUIRE(names_in(folder) == three);
    const std::string first = bytes_of(folder / "worker.1.log");
    const std::string second = bytes_of(folder / "worker.2.log");

    HeldOpen reader{folder / "worker.2.log"};
    lines.write(40);

    // worker.2.log can't become worker.3.log, so worker.1.log isn't put over
    // it, nor worker.log over that.
    CHECK(names_in(folder) == three);
    CHECK(bytes_of(folder / "worker.1.log") == first);
    CHECK(bytes_of(folder / "worker.2.log") == second);
    CHECK(all_lines_oldest_first(folder) == lines.written);
    CHECK(log->write_failures() == 0);

    reader.release();
    lines.write(1);

    CHECK(names_in(folder) ==
          std::set<std::string>{"worker.log", "worker.1.log", "worker.2.log", "worker.3.log"});
    CHECK(bytes_of(folder / "worker.2.log") == first);
    CHECK(bytes_of(folder / "worker.3.log") == second);
    CHECK(log_lines_after_time(folder) == std::vector<std::string>{lines.written.back()});
    CHECK(all_lines_oldest_first(folder) == lines.written);
    CHECK(log->write_failures() == 0);
}

TEST_CASE("a blocked rotation costs the oldest file once and no file after it", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info, {kKiB, 5});
    LineWriter lines{log, "the full set's reader"};

    for (int i = 0; i < 200 && !std::filesystem::exists(folder / "worker.4.log"); ++i) {
        lines.write(1);
    }
    const std::set<std::string> five{"worker.log", "worker.1.log", "worker.2.log", "worker.3.log",
                                     "worker.4.log"};
    REQUIRE(names_in(folder) == five);
    const std::string first = bytes_of(folder / "worker.1.log");
    const std::string second = bytes_of(folder / "worker.2.log");
    const std::string third = bytes_of(folder / "worker.3.log");

    // Every number is taken, so the first try gives up the oldest file, as a
    // rotation does, and stops at worker.1.log. The tries after it end at the
    // number that one left free: the old files stay where they are, however
    // many lines follow.
    HeldOpen reader{folder / "worker.1.log"};
    lines.write(60);

    CHECK(names_in(folder) ==
          std::set<std::string>{"worker.log", "worker.1.log", "worker.3.log", "worker.4.log"});
    CHECK(bytes_of(folder / "worker.1.log") == first);
    CHECK(bytes_of(folder / "worker.3.log") == second);
    CHECK(bytes_of(folder / "worker.4.log") == third);
    CHECK(log->write_failures() == 0);
    // What is left is the end of what was written, with no line missing in it.
    const std::vector<std::string> kept = all_lines_oldest_first(folder);
    REQUIRE(kept.size() <= lines.written.size());
    CHECK(std::equal(kept.rbegin(), kept.rend(), lines.written.rbegin()));

    reader.release();
    lines.write(1);

    CHECK(names_in(folder) == five);
    CHECK(bytes_of(folder / "worker.2.log") == first);
    CHECK(bytes_of(folder / "worker.3.log") == second);
    CHECK(bytes_of(folder / "worker.4.log") == third);
    CHECK(log_lines_after_time(folder) == std::vector<std::string>{lines.written.back()});
}

TEST_CASE("a rename refused half-way puts no file over one that stayed", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    std::filesystem::create_directories(folder);
    const std::filesystem::path file = folder / rp::kLogFileName;
    // Recorded as "<from> > <to>", and refused for the file named, if any.
    std::vector<std::string> renames;
    std::string refused;
    const auto rename = [&](const std::filesystem::path& from, const std::filesystem::path& to) {
        renames.push_back(from.filename().string() + " > " + to.filename().string());
        return from.filename().string() != refused && rp::detail::rename_log_file(from, to);
    };
    const auto log = std::make_shared<rp::ServiceLog>(
        rp::detail::make_log_file_sink(file, rp::detail::ansi_path(file).value(), {kKiB, 5}, rename),
        Level::info, file);
    LineWriter lines{log, "the refused rename"};

    for (int i = 0; i < 100 && !std::filesystem::exists(folder / "worker.2.log"); ++i) {
        lines.write(1);
    }
    REQUIRE(renames == std::vector<std::string>{"worker.log > worker.1.log",
                                                "worker.1.log > worker.2.log",
                                                "worker.log > worker.1.log"});
    const std::string first = bytes_of(folder / "worker.1.log");
    const std::string second = bytes_of(folder / "worker.2.log");

    renames.clear();
    refused = "worker.1.log";
    lines.write(40);

    // worker.2.log went up; worker.1.log stayed, so worker.log was never put
    // over it: not asked once.
    CHECK(names_in(folder) == std::set<std::string>{"worker.log", "worker.1.log", "worker.3.log"});
    CHECK(bytes_of(folder / "worker.1.log") == first);
    CHECK(bytes_of(folder / "worker.3.log") == second);
    CHECK(all_lines_oldest_first(folder) == lines.written);
    CHECK(log->write_failures() == 0);
    REQUIRE(renames.size() > 2);
    CHECK(renames.front() == "worker.2.log > worker.3.log");
    CHECK(std::all_of(renames.begin() + 1, renames.end(), [](const std::string& asked) {
        return asked == "worker.1.log > worker.2.log";
    }));

    renames.clear();
    refused.clear();
    lines.write(1);

    CHECK(renames == std::vector<std::string>{"worker.1.log > worker.2.log",
                                              "worker.log > worker.1.log"});
    CHECK(bytes_of(folder / "worker.2.log") == first);
    CHECK(all_lines_oldest_first(folder) == lines.written);
}

TEST_CASE("a worker.log that can't be opened after a rotation fails each line until it can",
          "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    std::filesystem::create_directories(folder);
    const std::filesystem::path file = folder / rp::kLogFileName;
    // The rotation is made; with `block`, a folder then stands where the new
    // worker.log would be opened.
    bool block = false;
    const auto rename = [&](const std::filesystem::path& from, const std::filesystem::path& to) {
        const bool renamed = rp::detail::rename_log_file(from, to);
        if (block) {
            std::filesystem::create_directory(file);
        }
        return renamed;
    };
    const auto log = std::make_shared<rp::ServiceLog>(
        rp::detail::make_log_file_sink(file, rp::detail::ansi_path(file).value(), {kKiB, 5}, rename),
        Level::info, file);
    LineWriter lines{log, "the log that won't open"};

    lines.write(15);
    REQUIRE(names_in(folder) == std::set<std::string>{"worker.log"});
    const std::vector<std::string> before = lines.written;

    block = true;
    log->logger()->info("the line that rotates, lost");
    CHECK(log->write_failures() == 1);
    // What was on disk is on disk: in worker.1.log, whole.
    CHECK(std::filesystem::is_directory(file));
    CHECK(lines_after_time(folder / "worker.1.log") == before);

    // Not silently: every line that finds no file is a failure, and counted.
    log->logger()->info("lost too");
    rp::log_security(log->logger(), "lost as well");
    CHECK(log->write_failures() == 3);
    // A flush has nothing to flush and fails nothing.
    log->flush();
    CHECK(log->write_failures() == 3);

    // The folder gone, the next line opens worker.log and is written.
    std::filesystem::remove(file);
    log->logger()->info("written again");
    log->logger()->info("and again");

    CHECK(log->write_failures() == 3);
    CHECK(log_lines_after_time(folder) ==
          std::vector<std::string>{"info written again", "info and again"});
    CHECK(lines_after_time(folder / "worker.1.log") == before);
    CHECK(names_in(folder) == std::set<std::string>{"worker.log", "worker.1.log"});
}

TEST_CASE("lines from several threads are whole lines", "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);
    const std::shared_ptr<spdlog::logger> logger = log->logger();

    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([logger, t] {
            for (int i = 0; i < 50; ++i) {
                logger->info("thread {} line {:02} password=secret{}", t, i, t);
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }

    const std::vector<std::string> lines = log_lines_after_time(folder);
    REQUIRE(lines.size() == 200);
    static const std::regex form{R"(^info thread [0-3] line \d\d password=\[REDACTED\]$)"};
    for (const std::string& line : lines) {
        CAPTURE(line);
        CHECK(std::regex_match(line, form));
    }
    CHECK(log->write_failures() == 0);
}

// --- A write that fails -----------------------------------------------------

TEST_CASE("a write that fails is counted, the line is lost, and nothing else changes",
          "[service_log]")
{
    const auto inner = std::make_shared<RecordingSink>();
    rp::ServiceLog log{inner, Level::info};
    const std::shared_ptr<spdlog::logger> logger = log.logger();

    logger->info("before");
    CHECK(log.write_failures() == 0);

    inner->fail_log = true;
    // Nothing reaches the caller: the service doesn't stop over its log.
    CHECK_NOTHROW(logger->info("lost password=hunter2"));
    CHECK_NOTHROW(rp::log_security(logger, "lost too"));
    CHECK(log.write_failures() == 2);

    inner->fail_log = false;
    logger->info("after");
    CHECK(log.write_failures() == 2);

    CHECK(inner->written == std::vector<std::string>{"before", "after"});
    // What the failing write was handed was redacted already: a line is never
    // written unredacted, failing or not.
    CHECK(inner->handed == std::vector<std::string>{"before", "lost password=[REDACTED]",
                                                    "SECURITY: lost too", "after"});
}

TEST_CASE("a flush that fails is counted too, by the line and by flush()", "[service_log]")
{
    const auto inner = std::make_shared<RecordingSink>();
    rp::ServiceLog log{inner, Level::info};

    inner->fail_flush = true;
    CHECK_NOTHROW(log.logger()->info("written, not flushed"));
    CHECK(log.write_failures() == 1);
    CHECK_NOTHROW(log.flush());
    CHECK(log.write_failures() == 2);
    CHECK_NOTHROW(log.logger()->flush());
    CHECK(log.write_failures() == 3);

    inner->fail_flush = false;
    log.flush();
    CHECK(log.write_failures() == 3);
    CHECK(inner->written == std::vector<std::string>{"written, not flushed"});
}

TEST_CASE("a message that can't be formatted is counted and writes nothing", "[service_log]")
{
    const auto inner = std::make_shared<RecordingSink>();
    rp::ServiceLog log{inner, Level::info};

    // spdlog's own failure path, before the sink: the same counter, and no
    // line on stderr from spdlog's default handler.
    log.logger()->info(fmt::runtime("{} and {}"), "one argument only");

    CHECK(log.write_failures() == 1);
    CHECK(inner->handed.empty());
}

TEST_CASE("each line is flushed by the sink, whatever the logger's flush level", "[service_log]")
{
    const auto inner = std::make_shared<RecordingSink>();
    rp::ServiceLog log{inner, Level::trace};

    log.logger()->trace("one");
    log.logger()->info("two");
    CHECK(inner->flushes == 2);
    // A line that isn't written costs no flush.
    log.set_level(Level::err);
    log.logger()->info("dropped");
    CHECK(inner->flushes == 2);
}

// --- Flushing and closing ---------------------------------------------------

TEST_CASE("close() lets go of the file, and what is logged afterwards goes nowhere",
          "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    const std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);
    const std::shared_ptr<spdlog::logger> logger = log->logger();
    logger->info("service stopped after 12 ms");

    // Open, the file can't be taken away.
    std::error_code ec;
    CHECK_FALSE(std::filesystem::remove(folder / rp::kLogFileName, ec));
    CHECK(ec);

    log->flush();
    log->close();

    const std::string text = bytes_of(folder / rp::kLogFileName);
    CHECK(lines_of(text).size() == 1);
    // A logger someone still holds writes nothing, fails nothing and throws
    // nothing.
    CHECK_NOTHROW(logger->info("after the close"));
    CHECK_NOTHROW(rp::log_security(logger, "after the close"));
    CHECK_NOTHROW(log->flush());
    CHECK_NOTHROW(log->close());
    CHECK(bytes_of(folder / rp::kLogFileName) == text);
    CHECK(log->write_failures() == 0);

    // Closed, it can.
    CHECK(std::filesystem::remove(folder / rp::kLogFileName, ec));
    CHECK_FALSE(ec);
}

TEST_CASE("close() flushes what the inner sink still holds", "[service_log]")
{
    const auto inner = std::make_shared<RecordingSink>();
    rp::ServiceLog log{inner, Level::info};

    log.close();
    CHECK(inner->flushes == 1);
    log.flush();
    log.close();
    CHECK(inner->flushes == 1);

    // A flush that fails at the close is counted, and the sink is let go all
    // the same.
    const auto failing = std::make_shared<RecordingSink>();
    failing->fail_flush = true;
    rp::ServiceLog other{failing, Level::info};
    CHECK_NOTHROW(other.close());
    CHECK(other.write_failures() == 1);
    CHECK(failing.use_count() == 1);
}

TEST_CASE("the file is closed when the last holder of the log and of its logger goes",
          "[service_log]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    std::shared_ptr<rp::ServiceLog> log = open_log(folder, Level::info);
    std::shared_ptr<spdlog::logger> logger = log->logger();
    logger->info("held");

    log.reset();
    // The logger alone still writes: W4.8's pipeline may hold only that.
    logger->info("by the logger alone");
    CHECK(log_lines_after_time(folder) ==
          std::vector<std::string>{"info held", "info by the logger alone"});

    logger.reset();
    std::error_code ec;
    CHECK(std::filesystem::remove(folder / rp::kLogFileName, ec));
}

// --- Handed on, never global ------------------------------------------------

TEST_CASE("the service's logger is neither registered with spdlog nor its default logger",
          "[service_log]")
{
    const TempDir tmp;
    const std::shared_ptr<spdlog::logger> default_before = spdlog::default_logger();

    const std::shared_ptr<rp::ServiceLog> log = open_log(tmp.path() / "logs", Level::info);

    REQUIRE(log->logger() != nullptr);
    CHECK(log->logger()->name() == "rpworker");
    CHECK(spdlog::get(log->logger()->name()) == nullptr);
    CHECK(spdlog::default_logger() == default_before);
    CHECK(spdlog::default_logger() != log->logger());
    // One sink, the one that redacts.
    REQUIRE(log->logger()->sinks().size() == 1);
    CHECK(std::dynamic_pointer_cast<rp::ServiceLogSink>(log->logger()->sinks().front()) != nullptr);
    // The same logger every time it is asked for.
    CHECK(log->logger() == log->logger());
}
