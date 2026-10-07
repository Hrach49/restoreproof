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

// `name` as UTF-8, for a test's message.
std::string as_utf8(const std::wstring& name)
{
    const std::u8string text = std::filesystem::path{name}.u8string();
    return {text.begin(), text.end()};
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
    const std::vector<std::wstring> plain{L"run.json", L"run", L"тест.json", L".run.json",
                                          L"a b.json"};
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

TEST_CASE("atomic file: a name ending in '.' or ' ' isn't plain: Win32 would write another name",
          "[atomic_file]")
{
    for (const std::wstring name : {L"run.json.", L"run.json ", L"...", L"run. ", L" "}) {
        CAPTURE(name.size());
        CHECK_FALSE(rp::is_plain_file_name(name));
    }
}

TEST_CASE("atomic file: a DOS device's name isn't plain, alone, with an extension, in any case",
          "[atomic_file]")
{
    // Win32 says "not found" for PRN, AUX, COM1 or LPT1 with no such device:
    // only the name rule stops them.
    for (const std::wstring name :
         {L"PRN", L"prn.json", L"AUX", L"aux.json", L"Nul", L"nul.tar.gz", L"CON", L"con.json",
          L"CONIN$", L"conout$.json", L"COM1", L"com9.json", L"LPT1", L"lpt1.json", L"COM0",
          L"LPT0.json", L"COM\u00b9", L"lpt\u00b2.json", L"LPT\u00b3", L"PRN .json", L"aux  .x"}) {
        CAPTURE(as_utf8(name));
        CHECK_FALSE(rp::is_plain_file_name(name));
    }
    for (const std::wstring name :
         {L"PRNT.json", L"auxiliary.json", L"console.json", L"nul_x.json", L"COM10", L"com.json",
          L"LPT", L"lpt10.json", L"COMA", L"xprn.json", L"run.prn", L"a.aux.json", L"COM\u00b4",
          L" PRN.json"}) {
        CAPTURE(as_utf8(name));
        CHECK(rp::is_plain_file_name(name));
    }
}

TEST_CASE("atomic file: the writer refuses a device's name or a trailing '.', and makes nothing",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    CHECK_FALSE(rp::write_file_atomically(dir.path() / "PRN.json", "this run"));
    CHECK_FALSE(rp::write_file_atomically(dir.path() / "run.json.", "this run"));
    CHECK(names_in(dir.path()).empty());
}

// --- Checking a path before a run (check_new_file) ---------------------------------

TEST_CASE("atomic file: check_new_file: a plain name in a folder it can write is ok, and leaves "
          "nothing behind",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    CHECK(rp::check_new_file(dir.path() / L"тест-run.json") == rp::NewFileCheck::ok);
    CHECK(names_in(dir.path()).empty());
}

TEST_CASE("atomic file: check_new_file: a name, a file already there, a missing folder, each said "
          "before anything is made",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path earlier = dir.write("earlier.json", "earlier run");

    CHECK(rp::check_new_file(dir.path() / "run.json:x") == rp::NewFileCheck::not_a_file_name);
    CHECK(rp::check_new_file(dir.path() / "PRN.json") == rp::NewFileCheck::not_a_file_name);
    CHECK(rp::check_new_file(dir.path() / "run.json.") == rp::NewFileCheck::not_a_file_name);
    CHECK(rp::check_new_file(earlier) == rp::NewFileCheck::exists);
    CHECK(rp::check_new_file(dir.path()) == rp::NewFileCheck::exists);
    CHECK(rp::check_new_file(dir.path() / "missing" / "run.json") == rp::NewFileCheck::no_folder);

    CHECK(names_in(dir.path()) == std::set<std::string>{"earlier.json"});
    CHECK(read_file(earlier) == "earlier run");
}

TEST_CASE("atomic file: check_new_file: a name too long once the temp's 21 characters are added "
          "can't be written, as the writer would find only at the end",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    // 240 units fit a 255-unit name; "<name>.<16 hex>.tmp" doesn't.
    const std::filesystem::path target = dir.path() / (std::string(235, 'r') + ".json");

    CHECK(rp::check_new_file(target) == rp::NewFileCheck::cannot_write);
    CHECK_FALSE(rp::write_file_atomically(target, "this run"));
    CHECK(names_in(dir.path()).empty());
}

TEST_CASE("atomic file: check_new_file: the temp name taken, or a suffix that isn't hex, can't be "
          "written; someone else's temp file is left as it was",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    const std::string temp_name = std::string{"run.json."} + kSuffix + ".tmp";
    const std::filesystem::path temp = dir.write(temp_name, "someone else's");

    CHECK(rp::check_new_file(dir.path() / "run.json", fixed_suffix()) ==
          rp::NewFileCheck::cannot_write);
    rp::AtomicWriteOptions bad;
    bad.temp_suffix = [] { return std::string{"not hex"}; };
    CHECK(rp::check_new_file(dir.path() / "run.json", bad) == rp::NewFileCheck::cannot_write);
    rp::AtomicWriteOptions throwing;
    throwing.temp_suffix = []() -> std::string { throw std::runtime_error("no"); };
    CHECK(rp::check_new_file(dir.path() / "run.json", throwing) == rp::NewFileCheck::cannot_write);

    CHECK(read_file(temp) == "someone else's");
    CHECK(names_in(dir.path()) == std::set<std::string>{temp_name});
}

TEST_CASE("atomic file: check_new_file then the writer: the check's temp file is gone, so the "
          "writer's own, with the same suffix, is made",
          "[atomic_file]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path target = dir.path() / "run.json";

    REQUIRE(rp::check_new_file(target, fixed_suffix()) == rp::NewFileCheck::ok);
    CHECK(rp::write_file_atomically(target, "this run", fixed_suffix()));

    CHECK(read_file(target) == "this run");
    CHECK(names_in(dir.path()) == std::set<std::string>{"run.json"});
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

// --- W4.6: the replacing writer (the outbox's manifest.json) --------------------------

TEST_CASE("atomic file: with replace the file at the target is replaced whole, and a new one is "
          "written as without it",
          "[atomic_file][outbox]")
{
    const rp::test::TempDir dir;
    rp::AtomicWriteOptions options = fixed_suffix();
    options.replace = true;
    const std::filesystem::path target = dir.write("manifest.json", "the earlier, longer text");

    CHECK(rp::write_file_atomically(target, "new", options));
    CHECK(read_file(target) == "new");
    CHECK(rp::write_file_atomically(dir.path() / "other.json", "first", options));
    CHECK(read_file(dir.path() / "other.json") == "first");
    CHECK(names_in(dir.path()) == std::set<std::string>{"manifest.json", "other.json"});
}

TEST_CASE("atomic file: with replace a write that fails leaves the earlier file as it was",
          "[atomic_file][outbox]")
{
    const rp::test::TempDir dir;
    rp::AtomicWriteOptions options = fixed_suffix();
    options.replace = true;
    const std::filesystem::path target = dir.write("manifest.json", "earlier");
    SECTION("the step before the move fails")
    {
        options.before_move = [] { throw std::runtime_error("stop"); };
        CHECK_FALSE(rp::write_file_atomically(target, "new", options));
    }
    SECTION("a folder is at the target")
    {
        const std::filesystem::path folder = dir.path() / "taken";
        std::filesystem::create_directory(folder);
        CHECK_FALSE(rp::write_file_atomically(folder, "new", options));
        CHECK(std::filesystem::is_directory(folder));
    }
    CHECK(read_file(target) == "earlier");
    CHECK_FALSE(std::filesystem::exists(dir.path() / (std::string{"manifest.json."} + kSuffix + ".tmp")));
}
