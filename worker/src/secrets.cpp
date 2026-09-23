#include <rp/secrets.hpp>

#include <cstdlib>

namespace rp {

namespace {

// The variable's value, or nullopt when it is unset or empty. _dupenv_s
// rather than getenv, which MSVC flags as unsafe (C4996).
std::optional<std::string> read_env(std::string_view name)
{
    char* buffer = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&buffer, &length, std::string{name}.c_str()) != 0 || buffer == nullptr) {
        return std::nullopt;
    }
    std::string value(buffer);
    std::free(buffer);
    return value.empty() ? std::nullopt : std::optional<std::string>{std::move(value)};
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
