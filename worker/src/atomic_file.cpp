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
#include <filesystem>
#include <format>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

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

// "<path>.<suffix>.tmp", the one temp name of the writer and of its check;
// nullopt for a file name that isn't plain or a suffix that isn't 16
// lower-case hex digits. Throws what the suffix's maker throws.
std::optional<std::wstring> temp_path_for(const std::filesystem::path& path,
                                          const AtomicWriteOptions& options)
{
    if (!is_plain_file_name(path.filename().native())) {
        return std::nullopt;
    }
    const std::string suffix = options.temp_suffix ? options.temp_suffix() : random_suffix();
    if (!is_suffix(suffix)) {
        return std::nullopt;
    }
    return path.native() + L"." + std::wstring(suffix.begin(), suffix.end()) + L".tmp";
}

// Whether `name` is a DOS device's name (is_plain_file_name).
bool is_device_name(std::wstring_view name)
{
    std::wstring_view base = name.substr(0, name.find(L'.'));
    while (!base.empty() && base.back() == L' ') {
        base.remove_suffix(1);
    }
    std::wstring upper;
    for (const wchar_t c : base) {
        upper.push_back(c >= L'a' && c <= L'z' ? static_cast<wchar_t>(c - L'a' + L'A') : c);
    }
    for (const std::wstring_view device : {L"CON", L"PRN", L"AUX", L"NUL", L"CONIN$", L"CONOUT$"}) {
        if (upper == device) {
            return true;
        }
    }
    if (upper.size() != 4 || !(upper.starts_with(L"COM") || upper.starts_with(L"LPT"))) {
        return false;
    }
    // Windows counts COM¹, COM² and COM³ as devices too.
    const wchar_t digit = upper.back();
    return (digit >= L'0' && digit <= L'9') || digit == L'\u00b9' || digit == L'\u00b2' ||
           digit == L'\u00b3';
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
    // "." and ".." end in '.'.
    if (name.empty() || name.back() == L'.' || name.back() == L' ') {
        return false;
    }
    const bool refused_character = std::ranges::any_of(name, [](wchar_t c) {
        return c < L' ' || std::wstring_view{L"<>:\"/\\|?*"}.find(c) != std::wstring_view::npos;
    });
    try {
        return !refused_character && !is_device_name(name);
    } catch (...) {
        return false;
    }
}

NewFileCheck check_new_file(const std::filesystem::path& path,
                            const AtomicWriteOptions& options) noexcept
{
    try {
        if (!is_plain_file_name(path.filename().native())) {
            return NewFileCheck::not_a_file_name;
        }
        std::error_code ec;
        if (std::filesystem::symlink_status(path, ec).type() !=
            std::filesystem::file_type::not_found) {
            return NewFileCheck::exists;
        }
        const std::filesystem::path folder =
            path.has_parent_path() ? path.parent_path() : std::filesystem::path{L"."};
        if (!std::filesystem::is_directory(folder, ec)) {
            return NewFileCheck::no_folder;
        }
        const std::optional<std::wstring> temp = temp_path_for(path, options);
        if (!temp) {
            return NewFileCheck::cannot_write;
        }
        const FileHandle probe(CreateFileW(temp->c_str(), GENERIC_WRITE | DELETE, 0, nullptr,
                                           CREATE_NEW,
                                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                                           nullptr));
        return probe.valid() ? NewFileCheck::ok : NewFileCheck::cannot_write;
    } catch (...) {
        return NewFileCheck::cannot_write;
    }
}

bool write_file_atomically(const std::filesystem::path& path, std::string_view content,
                           const AtomicWriteOptions& options) noexcept
{
    std::wstring temp;
    try {
        std::optional<std::wstring> made = temp_path_for(path, options);
        if (!made) {
            return false;
        }
        temp = std::move(*made);
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
    const DWORD flags =
        MOVEFILE_WRITE_THROUGH | (options.replace ? MOVEFILE_REPLACE_EXISTING : DWORD{0});
    ok = ok && MoveFileExW(temp.c_str(), path.c_str(), flags) != 0;
    if (!ok) {
        DeleteFileW(temp.c_str());
    }
    return ok;
}

} // namespace rp
