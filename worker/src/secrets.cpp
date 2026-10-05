#include <rp/secrets.hpp>

#include <rp/config.hpp>

#include "utf16.hpp"

#include <string>
#include <utility>

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
// value, when the value isn't valid UTF-16. The buffer the value is read into
// held a secret: it is zeroed before it goes, whichever way this returns
// (W4.3), and never changes its size, so no copy of it is left elsewhere.
std::optional<std::string> read_env(std::string_view name)
{
    // The names are ASCII constants, so widening byte by byte is exact.
    const std::wstring wide_name(name.begin(), name.end());
    std::wstring value(kMaxEnvValue + 1, L'\0');
    const struct Zeroed {
        std::wstring& buffer;
        ~Zeroed() { SecureZeroMemory(buffer.data(), buffer.size() * sizeof(wchar_t)); }
    } zeroed{value};
    const DWORD length = GetEnvironmentVariableW(wide_name.c_str(), value.data(), kMaxEnvValue + 1);
    // 0: unset, or set to "". Above the buffer: can't happen within the limit.
    if (length == 0 || length > kMaxEnvValue) {
        return std::nullopt;
    }
    std::optional<std::string> utf8 = utf16_to_utf8(std::wstring_view{value.data(), length});
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
            read_env(kEnvGraphCertPfxBase64), read_env(kEnvGraphCertPassword),
            read_env(kEnvSigningKeyBase64)};
}

std::vector<std::string> secret_values(const Secrets& secrets)
{
    std::vector<std::string> values;
    for (const std::optional<std::string>* secret :
         {&secrets.veeam_password, &secrets.graph_cert_pfx_base64, &secrets.graph_cert_password,
          &secrets.signing_key_base64}) {
        if (*secret && !(*secret)->empty()) {
            values.push_back(**secret);
        }
    }
    return values;
}

void require_veeam_secrets(const Secrets& secrets)
{
    for (const auto& [secret, name] : {std::pair{&secrets.veeam_username, kEnvVeeamUsername},
                                       std::pair{&secrets.veeam_password, kEnvVeeamPassword}}) {
        if (!secret->has_value() || (*secret)->empty()) {
            throw ConfigError(std::string{name}, std::string{name} + " is not set");
        }
    }
}

std::string_view mask_secret(const std::optional<std::string>& secret) noexcept
{
    return secret && !secret->empty() ? "**** (set)" : "(not set)";
}

} // namespace rp
