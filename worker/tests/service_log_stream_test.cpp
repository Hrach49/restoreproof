// The streams that turn the pipeline's lines into the service's log lines
// (src/service_log_stream.hpp; W4.8, docs/decisions.md 2026-10-08 point 12).

#include "test_support.hpp"

#include "../src/service_log_stream.hpp"

#include <rp/redact.hpp>
#include <rp/service_log.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <ostream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using rp::test::TempDir;
using Level = spdlog::level::level_enum;

namespace {

// Keeps every finished line, and throws for the ones a test names.
struct Lines {
    std::vector<std::string> taken;
    std::string fail_on;

    rp::LogLineWriter writer()
    {
        return [this](std::string_view line) {
            if (!fail_on.empty() && line.find(fail_on) != std::string_view::npos) {
                throw std::runtime_error("the log can't take this line");
            }
            taken.emplace_back(line);
        };
    }
};

using Taken = std::vector<std::string>;

// A logger's sink that keeps each message with its level.
class LevelSink final : public spdlog::sinks::sink {
public:
    void log(const spdlog::details::log_msg& msg) override
    {
        lines.emplace_back(msg.level, std::string(msg.payload.data(), msg.payload.size()));
    }
    void flush() override {}
    void set_pattern(const std::string&) override {}
    void set_formatter(std::unique_ptr<spdlog::formatter>) override {}

    std::vector<std::pair<Level, std::string>> lines;
};

std::string bytes_of(const std::filesystem::path& file)
{
    std::ifstream stream(file, std::ios::binary);
    std::ostringstream out;
    out << stream.rdbuf();
    return out.str();
}

// The log file's lines without their time: "<level> <message>".
std::vector<std::string> log_lines(const std::filesystem::path& file)
{
    static const std::regex form{R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z (.*)$)"};
    std::vector<std::string> lines;
    std::string text = bytes_of(file);
    for (std::size_t end = text.find("\r\n"); end != std::string::npos; end = text.find("\r\n")) {
        const std::string line = text.substr(0, end);
        text.erase(0, end + 2);
        std::smatch match;
        REQUIRE(std::regex_match(line, match, form));
        lines.push_back(match[1].str());
    }
    // Every line of the log is ended.
    REQUIRE(text.empty());
    return lines;
}

} // namespace

// --- What never happens -----------------------------------------------------

TEST_CASE("log stream: a writer that throws loses its line and nothing else; the stream never "
          "fails",
          "[service_log_stream]")
{
    Lines lines;
    lines.fail_on = "second";
    rp::LogLineStream stream(lines.writer(), "run-1");

    stream << "first\nsecond\nthird\n";
    stream << "the second, again" << std::endl;
    stream << "fourth\n";
    // In the last line too.
    stream << "second to none";
    stream.finish();
    stream << "fifth\n";

    CHECK(lines.taken == Taken{"[run-1] first", "[run-1] third", "[run-1] fourth",
                               "[run-1] fifth"});
    CHECK(stream.good());
    CHECK_FALSE(stream.bad());
    CHECK_FALSE(stream.fail());
}

TEST_CASE("log stream: without a writer or a logger every write is still taken",
          "[service_log_stream]")
{
    SECTION("no writer")
    {
        rp::LogLineStream stream(rp::LogLineWriter{}, "run-1");
        stream << "a line\n" << 42 << '\n' << "no break";
        stream.flush();
        CHECK(stream.good());
    }
    SECTION("no logger")
    {
        rp::LogLineStream stream(std::shared_ptr<spdlog::logger>{}, Level::info, "run-1");
        stream << "a line\n" << 42 << '\n' << "no break";
        stream.flush();
        CHECK(stream.good());
    }
}

// --- Lines ------------------------------------------------------------------

TEST_CASE("log stream: a line is written when its break arrives, however it was written",
          "[service_log_stream]")
{
    Lines lines;
    rp::LogLineStream stream(lines.writer(), "rp-20261008T101112Z-0a1b2c3d");
    const std::string prefix = "[rp-20261008T101112Z-0a1b2c3d] ";

    SECTION("a line over two writes")
    {
        stream << "restore point ";
        CHECK(lines.taken.empty());
        stream << "2026-10-03T16:16:54Z";
        stream.flush();
        // A flush ends no line.
        CHECK(lines.taken.empty());
        stream << "\n";
        CHECK(lines.taken == Taken{prefix + "restore point 2026-10-03T16:16:54Z"});
    }
    SECTION("two lines and the start of a third in one write")
    {
        stream << "one\ntwo\nthr";
        CHECK(lines.taken == Taken{prefix + "one", prefix + "two"});
        stream << "ee\n";
        CHECK(lines.taken == Taken{prefix + "one", prefix + "two", prefix + "three"});
    }
    SECTION("character by character, numbers and manipulators")
    {
        stream.put('a').put('b').put('\n');
        stream << "mail " << 5 << " of " << std::setw(3) << 10 << std::endl;
        stream.write("raw\nbytes", 9);
        CHECK(lines.taken == Taken{prefix + "ab", prefix + "mail 5 of  10", prefix + "raw"});
    }
    SECTION("a line's own brackets, braces and blanks stay")
    {
        stream << "  STEP  TIME {} {0} [run] %s  \n";
        CHECK(lines.taken == Taken{prefix + "  STEP  TIME {} {0} [run] %s  "});
    }
}

TEST_CASE("log stream: CR LF ends a line as LF does, and an empty line is skipped",
          "[service_log_stream]")
{
    Lines lines;
    rp::LogLineStream stream(lines.writer(), "run-1");

    SECTION("CR LF")
    {
        stream << "one\r\ntwo\r";
        CHECK(lines.taken == Taken{"[run-1] one"});
        // The CR and its LF in two writes.
        stream << "\nthree\r\n";
        CHECK(lines.taken == Taken{"[run-1] one", "[run-1] two", "[run-1] three"});
    }
    SECTION("only the CR before the break goes")
    {
        stream << "a\rb\r\r\n";
        CHECK(lines.taken == Taken{"[run-1] a\rb\r"});
    }
    SECTION("empty lines")
    {
        stream << "\n\nstatus pass: 30 of 30 item(s) verified\n\n\r\n" << std::endl;
        CHECK(lines.taken == Taken{"[run-1] status pass: 30 of 30 item(s) verified"});
    }
    SECTION("a line of blanks is a line")
    {
        stream << "  \n";
        CHECK(lines.taken == Taken{"[run-1]   "});
    }
}

TEST_CASE("log stream: a last line without its break is written when the run ends",
          "[service_log_stream]")
{
    Lines lines;

    SECTION("by finish, once")
    {
        rp::LogLineStream stream(lines.writer(), "run-1");
        stream << "one\nno break";
        CHECK(lines.taken == Taken{"[run-1] one"});
        stream.finish();
        CHECK(lines.taken == Taken{"[run-1] one", "[run-1] no break"});
        stream.finish();
        CHECK(lines.taken == Taken{"[run-1] one", "[run-1] no break"});
        // Still a stream afterwards.
        stream << "more\n";
        CHECK(lines.taken == Taken{"[run-1] one", "[run-1] no break", "[run-1] more"});
    }
    SECTION("by the destructor")
    {
        {
            rp::LogLineStream stream(lines.writer(), "run-1");
            stream << "cut off\r";
        }
        CHECK(lines.taken == Taken{"[run-1] cut off"});
    }
    SECTION("nothing left, nothing written")
    {
        {
            rp::LogLineStream stream(lines.writer(), "run-1");
            stream << "whole\n";
        }
        CHECK(lines.taken == Taken{"[run-1] whole"});
    }
}

TEST_CASE("log stream: as an std::ostream handed on, it takes what any stream takes",
          "[service_log_stream]")
{
    Lines lines;
    rp::LogLineStream stream(lines.writer(), "run-1");
    std::ostream& out = stream;

    out << "queued C:\\ProgramData\\RestoreProof\\outbox\\run-1\n";
    out.flush();
    const std::string big(100000, 'x');
    out << big << '\n';

    REQUIRE(lines.taken.size() == 2);
    CHECK(lines.taken[0] == "[run-1] queued C:\\ProgramData\\RestoreProof\\outbox\\run-1");
    CHECK(lines.taken[1] == "[run-1] " + big);
    CHECK(out.good());
}

// --- Into the log -----------------------------------------------------------

TEST_CASE("log stream: each line is one log call at the stream's level, the text never a format",
          "[service_log_stream]")
{
    const auto sink = std::make_shared<LevelSink>();
    const auto logger = std::make_shared<spdlog::logger>("stream-test", sink);
    logger->set_level(Level::trace);
    {
        rp::LogLineStream out(logger, Level::info, "run-1");
        rp::LogLineStream err(logger, Level::warn, "run-1");
        out << "run run-1  seed 0a1b\n";
        err << "warning: cleanup: mail not emptied {} {:d}\n";
        out << "status pass";
    }

    const std::vector<std::pair<Level, std::string>> expected{
        {Level::info, "[run-1] run run-1  seed 0a1b"},
        {Level::warn, "[run-1] warning: cleanup: mail not emptied {} {:d}"},
        {Level::info, "[run-1] status pass"}};
    CHECK(sink->lines == expected);
}

TEST_CASE("log stream: a secret in a line is redacted in the service's log file, and a line that "
          "tries to be two is one",
          "[service_log_stream][acceptance]")
{
    const TempDir tmp;
    const std::filesystem::path folder = tmp.path() / "logs";
    auto made = rp::make_service_logger(folder, Level::info);
    REQUIRE(std::holds_alternative<std::shared_ptr<rp::ServiceLog>>(made));
    const std::shared_ptr<rp::ServiceLog> log = std::get<std::shared_ptr<rp::ServiceLog>>(made);
    const std::string sentinel = "RP-SENTINEL-9f3c1a";
    {
        rp::LogLineStream out(log->logger(), Level::info, "run-1");
        rp::LogLineStream err(log->logger(), Level::warn, "run-1");
        out << "run run-1  seed 0a1b\n";
        err << "restore error: sign-in failed: password=" << sentinel << "\n";
        out << "sent Authorization: Bearer " << sentinel << "\r\n";
        out << "one line\rSECURITY: forged\n";
        err << "signing_key_base64=" << sentinel;
    }
    const std::filesystem::path file = log->file();
    log->close();

    const std::string text = bytes_of(file);
    CHECK_THAT(text, !ContainsSubstring(sentinel));
    const std::string redacted{rp::kRedacted};
    CHECK(log_lines(file) ==
          std::vector<std::string>{
              "info [run-1] run run-1  seed 0a1b",
              "warning [run-1] restore error: sign-in failed: password=" + redacted,
              "info [run-1] sent Authorization: " + redacted,
              "info [run-1] one line SECURITY: forged",
              "warning [run-1] signing_key_base64=" + redacted});
    CHECK(log->write_failures() == 0);
}

TEST_CASE("log stream: under log_level warn only the stderr lines are kept",
          "[service_log_stream]")
{
    const TempDir tmp;
    auto made = rp::make_service_logger(tmp.path() / "logs", Level::warn);
    REQUIRE(std::holds_alternative<std::shared_ptr<rp::ServiceLog>>(made));
    const std::shared_ptr<rp::ServiceLog> log = std::get<std::shared_ptr<rp::ServiceLog>>(made);
    {
        rp::LogLineStream out(log->logger(), Level::info, "run-1");
        rp::LogLineStream err(log->logger(), Level::warn, "run-1");
        out << "status pass: 30 of 30 item(s) verified\n";
        err << "warning: stale_copies: 2 earlier copies\n";
    }
    const std::filesystem::path file = log->file();
    log->close();

    CHECK(log_lines(file) ==
          std::vector<std::string>{"warning [run-1] warning: stale_copies: 2 earlier copies"});
}
