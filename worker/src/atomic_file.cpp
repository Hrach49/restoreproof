#include "atomic_file.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <random>
#include <string>
#include <string_view>

namespace rp {

namespace {

constexpr std::size_t kSuffixDigits = 16;
// WriteFile takes a DWORD count: write in pieces well below it.
constexpr std::size_t kChunkBytes = std::size_t{1} << 30;

std::string random_suffix()
{
    std::random_device random;
    const std::uint64_t value = (static_cast<std::uint64_t>(random()) << 32) | random();
    return std::format("{:016x}", value);
}

// 16 lower-case hex digits.
bool is_suffix(std::string_view text) noexcept
{
    return text.size() == kSuffixDigits && std::ranges::all_of(text, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

// Closes the handle it holds when it goes.
class FileHandle {
public:
    explicit FileHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~FileHandle() { close(); }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;

    bool valid() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const noexcept { return handle_; }

    // Whether the handle closed cleanly.
    bool close() noexcept
    {
        if (!valid()) {
            return true;
        }
        const bool closed = CloseHandle(handle_) != 0;
        handle_ = INVALID_HANDLE_VALUE;
        return closed;
    }

private:
    HANDLE handle_;
};

bool write_all(HANDLE file, std::string_view content) noexcept
{
    while (!content.empty()) {
        const DWORD piece = static_cast<DWORD>(std::min(content.size(), kChunkBytes));
        DWORD written = 0;
        if (!WriteFile(file, content.data(), piece, &written, nullptr) || written == 0) {
            return false;
        }
        content.remove_prefix(written);
    }
    return true;
}

} // namespace

bool is_plain_file_name(std::wstring_view name) noexcept
{
    if (name.empty() || name == L"." || name == L"..") {
        return false;
    }
    return std::ranges::none_of(name, [](wchar_t c) {
        return c < L' ' || std::wstring_view{L"<>:\"/\\|?*"}.find(c) != std::wstring_view::npos;
    });
}

bool write_file_atomically(const std::filesystem::path& path, std::string_view content,
                           const AtomicWriteOptions& options) noexcept
{
    std::wstring temp;
    try {
        if (!is_plain_file_name(path.filename().native())) {
            return false;
        }
        const std::string suffix = options.temp_suffix ? options.temp_suffix() : random_suffix();
        if (!is_suffix(suffix)) {
            return false;
        }
        temp = path.native() + L"." + std::wstring(suffix.begin(), suffix.end()) + L".tmp";
    } catch (...) {
        return false;
    }
    FileHandle file(CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        // Nothing of ours to delete: a name already taken is someone else's.
        return false;
    }
    bool ok = write_all(file.get(), content) && FlushFileBuffers(file.get()) != 0;
    ok = file.close() && ok;
    if (ok && options.before_move) {
        try {
            options.before_move();
        } catch (...) {
            ok = false;
        }
    }
    ok = ok && MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok) {
        DeleteFileW(temp.c_str());
    }
    return ok;
}

} // namespace rp
