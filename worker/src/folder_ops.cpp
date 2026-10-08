#include "folder_ops.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace rp {

namespace {

// The mount point `p` is under, without an extended-length prefix; nullopt
// when Windows can't say.
std::optional<std::wstring> volume_of(const std::filesystem::path& p)
{
    constexpr std::wstring_view kExtended = LR"(\\?\)";
    constexpr std::wstring_view kExtendedShare = LR"(\\?\UNC\)";
    std::error_code ec;
    const std::filesystem::path full = std::filesystem::absolute(p, ec);
    if (ec) {
        return std::nullopt;
    }
    // The mount point is a prefix of the path, so the path's length is room
    // enough; MAX_PATH in case the call wants it.
    std::wstring buffer(std::max<std::size_t>(full.native().size(), MAX_PATH) + 1, L'\0');
    if (GetVolumePathNameW(full.c_str(), buffer.data(), static_cast<DWORD>(buffer.size())) == 0) {
        return std::nullopt;
    }
    buffer.resize(std::wcslen(buffer.data()));
    if (buffer.starts_with(kExtendedShare)) {
        return L"\\\\" + buffer.substr(kExtendedShare.size());
    }
    if (buffer.starts_with(kExtended)) {
        return buffer.substr(kExtended.size());
    }
    return buffer;
}

} // namespace

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

unsigned long make_folder_error(const std::filesystem::path& folder) noexcept
{
    try {
        std::error_code ec;
        std::filesystem::create_directories(folder, ec);
        if (path_kind(folder) == PathKind::folder) {
            return 0;
        }
        return ec ? static_cast<unsigned long>(ec.value()) : ERROR_DIRECTORY;
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

std::filesystem::path own_executable_path()
{
    // Long enough for any path Windows hands out (32,767 characters).
    std::wstring buffer(32'768, L' ');
    const DWORD length =
        GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) {
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                "GetModuleFileNameW");
    }
    buffer.resize(length);
    return std::filesystem::path{std::move(buffer)};
}

std::optional<bool> same_volume(const std::filesystem::path& a,
                                const std::filesystem::path& b) noexcept
{
    try {
        const std::optional<std::wstring> first = volume_of(a);
        const std::optional<std::wstring> second = volume_of(b);
        if (!first || !second) {
            return std::nullopt;
        }
        return _wcsicmp(first->c_str(), second->c_str()) == 0;
    } catch (...) {
        return std::nullopt;
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
