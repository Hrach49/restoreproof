#pragma once

// Helpers shared by the tests: a temp directory that removes itself and an
// environment variable that is put back as it was. Tests never write outside
// temp_directory_path() and never leave the environment changed.

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
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
    std::filesystem::path write(const std::string& name, std::string_view content) const
    {
        const std::filesystem::path file = path_ / name;
        std::ofstream stream(file, std::ios::binary);
        stream.write(content.data(), static_cast<std::streamsize>(content.size()));
        return file;
    }

private:
    std::filesystem::path path_;
};

// The value of an environment variable, or nullopt when it is unset.
inline std::optional<std::string> get_env(const std::string& name)
{
    char* buffer = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&buffer, &length, name.c_str()) != 0 || buffer == nullptr) {
        return std::nullopt;
    }
    std::string value(buffer);
    std::free(buffer);
    return value;
}

// Sets (or, with nullopt, unsets) an environment variable for the lifetime of
// the object, then restores the original value.
class ScopedEnv {
public:
    ScopedEnv(std::string_view name, const std::optional<std::string>& value)
        : name_(name), original_(get_env(name_))
    {
        set(value);
    }

    ~ScopedEnv() { set(original_); }

    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;

private:
    // On Windows, _putenv_s with an empty value removes the variable, so an
    // empty value can't be set; tests treat "" and unset alike.
    void set(const std::optional<std::string>& value)
    {
        _putenv_s(name_.c_str(), value ? value->c_str() : "");
    }

    std::string name_;
    std::optional<std::string> original_;
};

} // namespace rp::test
