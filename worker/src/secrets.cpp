#include <rp/secrets.hpp>

#include <rp/config.hpp>

#include "utf16.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace rp {

namespace {

// The longest value Windows allows in an environment variable, in UTF-16 units.
constexpr DWORD kMaxEnvValue = 32767;

// The variable's value as UTF-8, or nullopt when it is unset or empty. Read
// from the process's own UTF-16 environment: the CRT's narrow copy
// (getenv, _dupenv_s) is in the ANSI code page, which would silently change
// any character outside it. Throws ConfigError naming the variable, never its
// value, when the value isn't valid UTF-16.
std::optional<std::string> read_env(std::string_view name)
{
    // The names are ASCII constants, so widening byte by byte is exact.
    const std::wstring wide_name(name.begin(), name.end());
    std::wstring value(kMaxEnvValue + 1, L'\0');
    const DWORD length = GetEnvironmentVariableW(wide_name.c_str(), value.data(), kMaxEnvValue + 1);
    // 0: unset, or set to "". Above the buffer: can't happen within the limit.
    if (length == 0 || length > kMaxEnvValue) {
        return std::nullopt;
    }
    value.resize(length);
    std::optional<std::string> utf8 = utf16_to_utf8(value);
    if (!utf8) {
        throw ConfigError(std::string{name},
                          "environment variable " + std::string{name} + " is not valid Unicode");
    }
    return utf8;
}

} // namespace

Secrets load_secrets_from_env()
{
    return {read_env(kEnvVeeamUsername), read_env(kEnvVeeamPassword),
            read_env(kEnvGraphClientSecret)};
}

std::string_view mask_secret(const std::optional<std::string>& secret) noexcept
{
    return secret && !secret->empty() ? "**** (set)" : "(not set)";
}

} // namespace rp
