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

TEST_CASE("list_folder of an empty folder is an empty list, of no folder nothing", "[file_read]")
{
    const TempDir dir;
    const std::optional<std::vector<std::string>> none = rp::list_folder(dir.path());
    REQUIRE(none);
    CHECK(none->empty());
    CHECK_FALSE(rp::list_folder(dir.path() / "no-such-folder"));
    CHECK_FALSE(rp::list_folder(dir.write("a-file", "x")));
}
