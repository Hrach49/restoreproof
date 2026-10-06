#pragma once

// Helpers shared by the tests: a temp directory that removes itself and an
// environment variable that is put back as it was. Tests never write outside
// temp_directory_path() and never leave the environment changed.

#include <catch2/catch_test_macros.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
#include <streambuf>
#include <string>
#include <string_view>

namespace rp::test {

// A fresh, uniquely named directory under temp_directory_path(), removed with
// everything in it when the object goes away.
class TempDir {
public:
    TempDir()
    {
        std::random_device rd;
        const unsigned long long id = (static_cast<unsigned long long>(rd()) << 32) | rd();
        path_ = std::filesystem::temp_directory_path() / ("rp-test-" + std::to_string(id));
        std::filesystem::create_directories(path_);
    }

    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    const std::filesystem::path& path() const { return path_; }

    // Writes `content` byte for byte to `name` inside the directory.
    std::filesystem::path write(const std::filesystem::path& name, std::string_view content) const
    {
        const std::filesystem::path file = path_ / name;
        std::ofstream stream(file, std::ios::binary);
        stream.write(content.data(), static_cast<std::streamsize>(content.size()));
        stream.close();
        // A failed write would leave the test checking the wrong thing.
        REQUIRE(stream);
        return file;
    }

private:
    std::filesystem::path path_;
};

// Makes an empty file by its wide name, which may hold what isn't valid UTF-16
// (a lone surrogate: NTFS takes any 16-bit units). False when the file system
// refuses the name.
inline bool create_empty_file(const std::filesystem::path& file)
{
    const HANDLE handle = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(handle);
    return true;
}

// UTF-8 to UTF-16 and back, for the wide Windows APIs. Test data is always
// valid, so a failed conversion fails the test.
inline std::wstring widen(std::string_view utf8)
{
    if (utf8.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                                         static_cast<int>(utf8.size()), nullptr, 0);
    REQUIRE(size > 0);
    std::wstring wide(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()),
                        wide.data(), size);
    return wide;
}

inline std::string narrow(std::wstring_view wide)
{
    if (wide.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
                                         static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    REQUIRE(size > 0);
    std::string utf8(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), static_cast<int>(wide.size()),
                        utf8.data(), size, nullptr, nullptr);
    return utf8;
}

// The value of an environment variable as UTF-16, or nullopt when it is unset.
// Read through the CRT's wide copy of the environment, which _wputenv_s keeps
// in step with the process's own.
inline std::optional<std::wstring> get_env_wide(std::string_view name)
{
    wchar_t* buffer = nullptr;
    std::size_t length = 0;
    if (_wdupenv_s(&buffer, &length, widen(name).c_str()) != 0 || buffer == nullptr) {
        return std::nullopt;
    }
    std::wstring value(buffer);
    std::free(buffer);
    return value;
}

// The value of an environment variable as UTF-8, or nullopt when it is unset.
inline std::optional<std::string> get_env(std::string_view name)
{
    const std::optional<std::wstring> value = get_env_wide(name);
    return value ? std::optional<std::string>{narrow(*value)} : std::nullopt;
}

// Sets (or, with nullopt, unsets) an environment variable for the lifetime of
// the object, then restores the original value. Values go in as UTF-16 through
// _wputenv_s, which, like a variable inherited at startup, updates the
// process's environment and both of the CRT's copies (the narrow one in the
// ANSI code page).
class ScopedEnv {
public:
    // `value` is UTF-8.
    ScopedEnv(std::string_view name, const std::optional<std::string>& value)
        : name_(widen(name)), original_(get_env_wide(name))
    {
        set(value ? std::optional<std::wstring>{widen(*value)} : std::nullopt);
    }

    // For values UTF-8 can't express, such as an unpaired surrogate.
    ScopedEnv(std::string_view name, const std::wstring& value)
        : name_(widen(name)), original_(get_env_wide(name))
    {
        set(value);
    }

    ~ScopedEnv() { set(original_); }

    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;

private:
    // On Windows, _wputenv_s with an empty value removes the variable, so an
    // empty value can't be set; tests treat "" and unset alike.
    void set(const std::optional<std::wstring>& value)
    {
        _wputenv_s(name_.c_str(), value ? value->c_str() : L"");
    }

    std::wstring name_;
    std::optional<std::wstring> original_;
};

// A stream buffer that takes no bytes. An std::ostream on it with
// exceptions(std::ios::badbit) throws std::ios_base::failure on the first
// write: an exception from inside a command that the command doesn't expect.
class FailingStreamBuf : public std::streambuf {
protected:
    int_type overflow(int_type) override { return traits_type::eof(); }
    std::streamsize xsputn(const char*, std::streamsize) override { return 0; }
};

} // namespace rp::test
