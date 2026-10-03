// W3.6: the atomic writer behind `rpworker test --json <file>`
// (src/atomic_file.hpp): a temp file beside the target, flushed, then moved
// onto it, never over a file already there. Each test writes in its own temp
// folder. The choices are the 2026-10-03 W3.6 entry in docs/decisions.md,
// point 5.

#include "test_support.hpp"

#include "../src/atomic_file.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

// The names in `dir`, as UTF-8.
std::set<std::string> names_in(const std::filesystem::path& dir)
{
    std::set<std::string> names;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        const std::u8string name = entry.path().filename().u8string();
        names.emplace(name.begin(), name.end());
    }
    return names;
}

std::optional<std::string> read_file(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    return std::string{std::istreambuf_iterator<char>(file), {}};
}

constexpr const char* kSuffix = "0123456789abcdef";

rp::AtomicWriteOptions fixed_suffix()
{
    rp::AtomicWriteOptions options;
    options.temp_suffix = [] { return std::string{kSuffix}; };
    return options;
}

} // namespace

// --- Failure paths -------------------------------------------------------------------

TEST_CASE("atomic file: a target that exists is never replaced, and no temp file is left",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path target = dir.write("run.json", "earlier run");

    CHECK_FALSE(rp::write_file_atomically(target, "this run"));

    CHECK(read_file(target) == "earlier run");
    CHECK(names_in(dir.path()) == std::set<std::string>{"run.json"});
}

TEST_CASE("atomic file: a temp name already taken fails and is left as it was", "[atomic_file]")
{
    const rp::test::TempDir dir;
    const std::string temp_name = std::string{"run.json."} + kSuffix + ".tmp";
    const std::filesystem::path temp = dir.write(temp_name, "someone else's");
    const std::filesystem::path target = dir.path() / "run.json";

    CHECK_FALSE(rp::write_file_atomically(target, "this run", fixed_suffix()));

    CHECK_FALSE(std::filesystem::exists(target));
    CHECK(read_file(temp) == "someone else's");
    CHECK(names_in(dir.path()) == std::set<std::string>{temp_name});
}

TEST_CASE("atomic file: a folder that doesn't exist fails and makes nothing", "[atomic_file]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path target = dir.path() / "missing" / "run.json";

    CHECK_FALSE(rp::write_file_atomically(target, "this run"));

    CHECK(names_in(dir.path()).empty());
}

TEST_CASE("atomic file: a file that appears between the check and the move is never overwritten; "
          "the temp file is deleted",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path target = dir.path() / "run.json";
    rp::AtomicWriteOptions options = fixed_suffix();
    bool temp_was_there = false;
    options.before_move = [&] {
        temp_was_there = read_file(dir.path() / (std::string{"run.json."} + kSuffix + ".tmp")) ==
                         "this run";
        dir.write("run.json", "a scheduled script's");
    };

    CHECK_FALSE(rp::write_file_atomically(target, "this run", options));

    CHECK(temp_was_there);
    CHECK(read_file(target) == "a scheduled script's");
    CHECK(names_in(dir.path()) == std::set<std::string>{"run.json"});
}

TEST_CASE("atomic file: a hook that throws before the move fails, the temp file deleted",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    rp::AtomicWriteOptions options;
    options.before_move = [] { throw std::runtime_error("no"); };

    CHECK_FALSE(rp::write_file_atomically(dir.path() / "run.json", "this run", options));

    CHECK(names_in(dir.path()).empty());
}

TEST_CASE("atomic file: a temp suffix that isn't 16 lower-case hex digits is refused",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    for (const std::string suffix : {"", "0123456789ABCDEF", "0123456789abcde", "..\\..\\x0123456",
                                     "0123456789abcdef0"}) {
        CAPTURE(suffix);
        rp::AtomicWriteOptions options;
        options.temp_suffix = [suffix] { return suffix; };
        CHECK_FALSE(rp::write_file_atomically(dir.path() / "run.json", "this run", options));
    }
    rp::AtomicWriteOptions throwing;
    throwing.temp_suffix = []() -> std::string { throw std::runtime_error("no"); };
    CHECK_FALSE(rp::write_file_atomically(dir.path() / "run.json", "this run", throwing));
    CHECK(names_in(dir.path()).empty());
}

TEST_CASE("atomic file: a ':' in the file name is refused before anything is opened: no stream, "
          "no empty file, an existing file untouched",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path earlier = dir.write("earlier.json", "earlier run");
    const auto earlier_time = std::filesystem::last_write_time(earlier);

    // On NTFS "run.json:x" names a stream of run.json: CreateFileW would make
    // an empty run.json to hold it.
    CHECK_FALSE(rp::write_file_atomically(dir.path() / "run.json:x", "this run"));
    CHECK_FALSE(rp::write_file_atomically(dir.path() / "earlier.json:x", "this run"));

    CHECK(names_in(dir.path()) == std::set<std::string>{"earlier.json"});
    CHECK(read_file(earlier) == "earlier run");
    CHECK(std::filesystem::last_write_time(earlier) == earlier_time);
    CHECK_FALSE(read_file(dir.path() / "earlier.json:x"));
}

TEST_CASE("atomic file: a plain file name: not empty, '.' or '..', no control character and none "
          "of < > : \" / \\ | ? *",
          "[atomic_file]")
{
    const std::vector<std::wstring> plain{L"run.json", L"run",      L"тест.json", L".run.json",
                                          L"a b.json", L"run.json.", L"..."};
    for (std::size_t i = 0; i < plain.size(); ++i) {
        CAPTURE(i);
        CHECK(rp::is_plain_file_name(plain[i]));
    }
    const std::vector<std::wstring> refused{
        L"",         L".",        L"..",       L"run.json:x", L"run?.json",
        L"a|b.json", L"a<b.json", L"a>b.json", L"a\"b.json",  L"a*b.json",
        L"a/b.json", L"a\\b.json", L"a\tb.json", std::wstring{L"a"} + L'\0' + L"b.json",
        L"a\x1f" L"b.json"};
    for (std::size_t i = 0; i < refused.size(); ++i) {
        CAPTURE(i);
        CHECK_FALSE(rp::is_plain_file_name(refused[i]));
    }
}

// --- Writing -------------------------------------------------------------------------

TEST_CASE("atomic file: the content lands whole at the path, by its wide name, nothing beside it",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    // Cyrillic is outside the ANSI code page: only the wide API keeps it.
    const std::filesystem::path target = dir.path() / L"тест-run.json";
    const std::string content = std::string(100000, 'x') + "\n";

    CHECK(rp::write_file_atomically(target, content));

    CHECK(read_file(target) == content);
    CHECK(names_in(dir.path()) == std::set<std::string>{"\xd1\x82\xd0\xb5\xd1\x81\xd1\x82-run.json"});
}

TEST_CASE("atomic file: an empty content is an empty file", "[atomic_file]")
{
    const rp::test::TempDir dir;
    CHECK(rp::write_file_atomically(dir.path() / "run.json", ""));
    CHECK(read_file(dir.path() / "run.json") == "");
}
