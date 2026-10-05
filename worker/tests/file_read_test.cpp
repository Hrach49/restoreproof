// Reading a whole file under a limit and a folder's files by name (W4.2's
// read-back, W4.3's folder verifier).

#include "../src/file_read.hpp"

#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

using rp::FileRead;
using rp::FileState;
using rp::test::TempDir;

TEST_CASE("read_whole_file gives a file's bytes as they are", "[file_read]")
{
    const TempDir dir;
    const std::string content("a\r\n\0\xff b", 8);
    const std::filesystem::path file = dir.write("a.bin", content);

    const FileRead read = rp::read_whole_file(file, content.size());
    CHECK(read.state == FileState::read);
    CHECK(read.bytes == content);
    // An empty file is a file.
    const FileRead empty = rp::read_whole_file(dir.write("empty", ""), 0);
    CHECK(empty.state == FileState::read);
    CHECK(empty.bytes.empty());
}

TEST_CASE("read_whole_file reads nothing of a file over the limit", "[file_read]")
{
    const TempDir dir;
    const std::filesystem::path file = dir.write("a.txt", "12345");
    const FileRead read = rp::read_whole_file(file, 4);
    CHECK(read.state == FileState::too_large);
    CHECK(read.bytes.empty());
}

TEST_CASE("read_whole_file says unreadable for what isn't a file there", "[file_read]")
{
    const TempDir dir;
    CHECK(rp::read_whole_file(dir.path() / "no-such-file", 100).state == FileState::unreadable);
    CHECK(rp::read_whole_file(dir.path() / "no-such-folder" / "a", 100).state ==
          FileState::unreadable);
    // A folder has no size and no bytes.
    CHECK(rp::read_whole_file(dir.path(), 1u << 20).state == FileState::unreadable);
}

TEST_CASE("folder_reader reads the folder's own files by name", "[file_read]")
{
    const TempDir dir;
    dir.write("result.json", "{}");
    // By its wide name: a narrow path would be read in the ANSI code page.
    dir.write(rp::test::widen("\xC3\x9C" "bersicht.txt"), "x");
    const rp::FileReader read = rp::folder_reader(dir.path());

    CHECK(read("result.json", 10).bytes == "{}");
    CHECK(read("result.json", 10).state == FileState::read);
    CHECK(read("result.json", 1).state == FileState::too_large);
    CHECK(read("\xC3\x9C" "bersicht.txt", 10).bytes == "x");
    CHECK(read("signature.json", 10).state == FileState::unreadable);
}

TEST_CASE("folder_reader opens nothing outside its folder", "[file_read]")
{
    const TempDir dir;
    dir.write("outside.txt", "secret");
    std::filesystem::create_directories(dir.path() / "run");
    dir.write("run/inside.txt", "in");
    const rp::FileReader read = rp::folder_reader(dir.path() / "run");
    REQUIRE(read("inside.txt", 10).state == FileState::read);

    for (const char* name : {"../outside.txt", "..\\outside.txt", "..", ".", "", "sub/inside.txt",
                             "inside.txt:stream", "inside.txt.", "NUL", "\xff" "inside.txt"}) {
        CAPTURE(name);
        const FileRead file = read(name, 100);
        CHECK(file.state == FileState::unreadable);
        CHECK(file.bytes.empty());
    }
    // Nor by its full path.
    CHECK(read((dir.path() / "outside.txt").string(), 100).state == FileState::unreadable);
}

TEST_CASE("list_folder names everything in the folder, sorted", "[file_read]")
{
    const TempDir dir;
    dir.write("result.json", "{}");
    dir.write("items.csv", "");
    dir.write(rp::test::widen("\xC3\x9C" "bersicht.txt"), "x");
    std::filesystem::create_directories(dir.path() / "a-folder");
    dir.write("a-folder/inside.txt", "x");

    const std::optional<std::vector<std::string>> names = rp::list_folder(dir.path());
    REQUIRE(names);
    CHECK(*names == std::vector<std::string>{"a-folder", "items.csv", "result.json",
                                             "\xC3\x9C" "bersicht.txt"});
}

// NTFS takes a name that isn't valid UTF-16. Such a file is only ever a note
// of `signer verify`, never a reason to stop: list_folder gives the name with
// the lone surrogate as the three bytes UTF-8 would give its code point.
TEST_CASE("list_folder names a file whose name isn't valid UTF-16, a lone surrogate kept",
          "[file_read]")
{
    const TempDir dir;
    dir.write("result.json", "{}");
    const std::wstring low_alone = {L'x', wchar_t{0xDC80}, L'y'};
    const std::wstring high_last = {L'a', wchar_t{0xD800}};
    const std::wstring high_then_letter = {wchar_t{0xD83D}, L'b'};
    const std::wstring low_then_high = {wchar_t{0xDE00}, wchar_t{0xD83D}};
    const std::wstring pair_then_high = {wchar_t{0xD83D}, wchar_t{0xDE00}, wchar_t{0xD83D}};
    for (const std::wstring& name :
         {low_alone, high_last, high_then_letter, low_then_high, pair_then_high}) {
        if (!rp::test::create_empty_file(dir.path() / name)) {
            SKIP("this file system refuses a file name that isn't valid UTF-16");
        }
    }

    std::optional<std::vector<std::string>> names;
    REQUIRE_NOTHROW(names = rp::list_folder(dir.path()));
    REQUIRE(names);
    // Sorted by byte, which is by code point: as verify_bundle.py sorts them.
    CHECK(*names == std::vector<std::string>{"a\xED\xA0\x80", "result.json", "x\xED\xB2\x80y",
                                             "\xED\xA0\xBD" "b", "\xED\xB8\x80\xED\xA0\xBD",
                                             "\xF0\x9F\x98\x80\xED\xA0\xBD"});
    // The reader opens no such name: it isn't UTF-8.
    CHECK(rp::folder_reader(dir.path())("x\xED\xB2\x80y", 10).state == FileState::unreadable);
}

TEST_CASE("name_code_points reads a listed name back, a lone surrogate as its own code point",
          "[file_read]")
{
    CHECK(rp::name_code_points("").empty());
    CHECK(rp::name_code_points("a.txt") == U"a.txt");
    CHECK(rp::name_code_points("\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80") ==
          std::u32string{0xE9, 0x20AC, 0x1F600});
    CHECK(rp::name_code_points("x\xED\xB2\x80y") == std::u32string{U'x', 0xDC80, U'y'});
    CHECK(rp::name_code_points("\xED\xA0\x80") == std::u32string{0xD800});
    CHECK(rp::name_code_points("\xF4\x8F\xBF\xBF") == std::u32string{0x10FFFF});
}

TEST_CASE("name_code_points gives U+FFFD for each byte that is no UTF-8, never a throw",
          "[file_read]")
{
    const char32_t bad = 0xFFFD;
    // A continuation byte alone, a lead byte at the end, a lead byte before a letter.
    CHECK(rp::name_code_points("\x80") == std::u32string{bad});
    CHECK(rp::name_code_points("a\xC3") == std::u32string{U'a', bad});
    CHECK(rp::name_code_points("\xE2\x82") == std::u32string{bad, bad});
    CHECK(rp::name_code_points("\xC3" "b") == std::u32string{bad, U'b'});
    // Bytes UTF-8 never has, an overlong form, past U+10FFFF.
    CHECK(rp::name_code_points("\xFF\xF8") == std::u32string{bad, bad});
    CHECK(rp::name_code_points("\xC0\xAF") == std::u32string{bad, bad});
    CHECK(rp::name_code_points("\xE0\x80\xAF") == std::u32string{bad, bad, bad});
    CHECK(rp::name_code_points("\xF0\x80\x80\xAF") == std::u32string{bad, bad, bad, bad});
    CHECK(rp::name_code_points("\xF4\x90\x80\x80") == std::u32string{bad, bad, bad, bad});
}

TEST_CASE("list_folder of an empty folder is an empty list, of no folder nothing", "[file_read]")
{
    const TempDir dir;
    const std::optional<std::vector<std::string>> none = rp::list_folder(dir.path());
    REQUIRE(none);
    CHECK(none->empty());
    CHECK_FALSE(rp::list_folder(dir.path() / "no-such-folder"));
    CHECK_FALSE(rp::list_folder(dir.write("a-file", "x")));
}
