// The outbox's calls into the file system (src/folder_ops.hpp; W4.6): one
// rename that is never a copy, a folder's size, removing one, making one, and
// what is at a path.

#include "../src/folder_ops.hpp"

#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>

namespace {

using std::filesystem::path;

std::string text_of(const path& file)
{
    std::ifstream stream(file, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), {}};
}

} // namespace

TEST_CASE("folder ops: a rename never replaces what is at the target, and says why it failed",
          "[folder_ops][outbox]")
{
    const rp::test::TempDir dir;
    std::filesystem::create_directories(dir.path() / "from");
    dir.write("from/a.txt", "a");
    std::filesystem::create_directories(dir.path() / "taken");
    dir.write("taken/b.txt", "b");

    // ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND.
    CHECK(rp::move_folder(dir.path() / "from", dir.path() / "taken") == 183ul);
    CHECK(rp::move_folder(dir.path() / "gone", dir.path() / "to") == 2ul);
    CHECK(rp::move_folder(dir.path() / "from", dir.path() / "no" / "such" / "to") == 3ul);
    CHECK(text_of(dir.path() / "from" / "a.txt") == "a");
    CHECK(text_of(dir.path() / "taken" / "b.txt") == "b");
    CHECK(rp::kNotSameVolume == 17ul);
}

TEST_CASE("folder ops: a folder is renamed whole", "[folder_ops][outbox]")
{
    const rp::test::TempDir dir;
    std::filesystem::create_directories(dir.path() / "from" / "inner");
    dir.write("from/a.txt", "a");
    dir.write("from/inner/b.txt", "bb");

    CHECK(rp::move_folder(dir.path() / "from", dir.path() / "to") == 0ul);

    CHECK_FALSE(std::filesystem::exists(dir.path() / "from"));
    CHECK(text_of(dir.path() / "to" / "a.txt") == "a");
    CHECK(text_of(dir.path() / "to" / "inner" / "b.txt") == "bb");
}

TEST_CASE("folder ops: a folder's size is its files' sizes, those of the folders inside included",
          "[folder_ops][outbox]")
{
    const rp::test::TempDir dir;
    std::filesystem::create_directories(dir.path() / "run" / "inner" / "empty");
    dir.write("run/a.txt", std::string(1000, 'a'));
    dir.write("run/inner/b.bin", std::string(234, 'b'));
    dir.write("run/zero", "");

    CHECK(rp::folder_bytes(dir.path() / "run") == 1234u);
    CHECK(rp::folder_bytes(dir.path() / "run" / "inner" / "empty") == 0u);
    CHECK_FALSE(rp::folder_bytes(dir.path() / "gone"));
    CHECK_FALSE(rp::folder_bytes(dir.path() / "run" / "a.txt"));
}

TEST_CASE("folder ops: removing a folder takes everything in it; one that isn't there is gone",
          "[folder_ops][outbox]")
{
    const rp::test::TempDir dir;
    std::filesystem::create_directories(dir.path() / "run" / "inner");
    dir.write("run/inner/b.bin", "b");

    CHECK(rp::remove_folder(dir.path() / "run"));
    CHECK_FALSE(std::filesystem::exists(dir.path() / "run"));
    CHECK(rp::remove_folder(dir.path() / "run"));

    // A file in use can't be removed: the folder is still there.
    std::filesystem::create_directories(dir.path() / "busy");
    const path held = dir.write("busy/held.txt", "x");
    {
        const HANDLE handle = CreateFileW(held.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
                                          FILE_ATTRIBUTE_NORMAL, nullptr);
        REQUIRE(handle != INVALID_HANDLE_VALUE);
        CHECK_FALSE(rp::remove_folder(dir.path() / "busy"));
        CloseHandle(handle);
    }
    CHECK(rp::remove_folder(dir.path() / "busy"));
}

TEST_CASE("folder ops: making a folder makes the levels above it; a file in the way stops it",
          "[folder_ops][outbox]")
{
    const rp::test::TempDir dir;

    CHECK(rp::make_folder(dir.path() / "a" / "b" / "c"));
    CHECK(rp::make_folder(dir.path() / "a" / "b" / "c"));
    CHECK(std::filesystem::is_directory(dir.path() / "a" / "b" / "c"));
    const path file = dir.write("file", "x");
    CHECK_FALSE(rp::make_folder(file));
    CHECK_FALSE(rp::make_folder(file / "under"));
}

TEST_CASE("folder ops: what is at a path is nothing, a folder, or anything else",
          "[folder_ops][outbox]")
{
    const rp::test::TempDir dir;
    const path file = dir.write("file", "x");

    CHECK(rp::path_kind(dir.path()) == rp::PathKind::folder);
    CHECK(rp::path_kind(file) == rp::PathKind::file);
    CHECK(rp::path_kind(dir.path() / "gone") == rp::PathKind::none);
    CHECK(rp::path_kind(file / "under") == rp::PathKind::none);
    CHECK(rp::path_kind(path{}) == rp::PathKind::none);
}
