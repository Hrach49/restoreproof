#pragma once

// A folder so deep that every file in it is past MAX_PATH (260 characters):
// what `rpworker signer verify` must read like any other folder.

#include "../src/file_read.hpp"

#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

namespace rp::test {

// Made below `dir` through its extended path, and taken away through it again,
// which TempDir's own remove can't do for names this long.
class DeepFolder {
public:
    explicit DeepFolder(const TempDir& dir) : top_(dir.path() / "deep"), path_(top_)
    {
        while (path_.native().size() < 245) {
            path_ /= "twenty-characters-ab";
        }
        std::filesystem::create_directories(rp::extended_folder(path_));
    }

    ~DeepFolder()
    {
        std::error_code ec;
        std::filesystem::remove_all(rp::extended_folder(top_), ec);
    }

    DeepFolder(const DeepFolder&) = delete;
    DeepFolder& operator=(const DeepFolder&) = delete;

    // As a caller names it: nothing in front of the drive.
    const std::filesystem::path& path() const { return path_; }

    void write(const std::string& name, std::string_view content) const
    {
        std::ofstream file(rp::extended_folder(path_) / name, std::ios::binary);
        file.write(content.data(), static_cast<std::streamsize>(content.size()));
        file.close();
        REQUIRE(file);
    }

    void remove(const std::string& name) const
    {
        REQUIRE(std::filesystem::remove(rp::extended_folder(path_) / name));
    }

private:
    std::filesystem::path top_;
    std::filesystem::path path_;
};

} // namespace rp::test
