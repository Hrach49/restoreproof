#include "folder_ops.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <system_error>

namespace rp {

unsigned long move_folder(const std::filesystem::path& from,
                          const std::filesystem::path& to) noexcept
{
    if (MoveFileExW(from.c_str(), to.c_str(), 0) != 0) {
        return 0;
    }
    const unsigned long error = GetLastError();
    // Never "it worked" for a call that failed.
    return error == 0 ? ERROR_GEN_FAILURE : error;
}

std::optional<std::uintmax_t> folder_bytes(const std::filesystem::path& folder) noexcept
{
    try {
        std::error_code ec;
        std::filesystem::recursive_directory_iterator it(folder, ec);
        if (ec) {
            return std::nullopt;
        }
        std::uintmax_t total = 0;
        for (const std::filesystem::recursive_directory_iterator end; it != end; it.increment(ec)) {
            if (ec) {
                return std::nullopt;
            }
            std::error_code file_ec;
            if (it->is_regular_file(file_ec)) {
                const std::uintmax_t size = it->file_size(file_ec);
                total += file_ec ? 0 : size;
            }
        }
        return ec ? std::nullopt : std::optional<std::uintmax_t>{total};
    } catch (...) {
        return std::nullopt;
    }
}

bool remove_folder(const std::filesystem::path& folder) noexcept
{
    try {
        std::error_code ec;
        std::filesystem::remove_all(folder, ec);
        return path_kind(folder) == PathKind::none;
    } catch (...) {
        return false;
    }
}

bool make_folder(const std::filesystem::path& folder) noexcept
{
    try {
        std::error_code ec;
        std::filesystem::create_directories(folder, ec);
        return path_kind(folder) == PathKind::folder;
    } catch (...) {
        return false;
    }
}

PathKind path_kind(const std::filesystem::path& path) noexcept
{
    try {
        std::error_code ec;
        const std::filesystem::file_status status = std::filesystem::symlink_status(path, ec);
        if (ec || status.type() == std::filesystem::file_type::not_found) {
            return PathKind::none;
        }
        return status.type() == std::filesystem::file_type::directory ? PathKind::folder
                                                                      : PathKind::file;
    } catch (...) {
        return PathKind::none;
    }
}

} // namespace rp
