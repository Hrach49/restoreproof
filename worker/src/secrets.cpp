#include <rp/secrets.hpp>

#include <rp/config.hpp>

#include <string>
#include <utility>

namespace rp {

namespace {

template <typename S, typename Field>
Field* field_of(S& secrets, std::string_view name) noexcept
{
    if (name == kNameVeeamUsername) {
        return &secrets.veeam_username;
    }
    if (name == kNameVeeamPassword) {
        return &secrets.veeam_password;
    }
    if (name == kNameGraphCertPfxBase64) {
        return &secrets.graph_cert_pfx_base64;
    }
    if (name == kNameGraphCertPassword) {
        return &secrets.graph_cert_password;
    }
    if (name == kNameSigningKeyBase64) {
        return &secrets.signing_key_base64;
    }
    return nullptr;
}

} // namespace

std::optional<std::string>* secret_field(Secrets& secrets, std::string_view name) noexcept
{
    return field_of<Secrets, std::optional<std::string>>(secrets, name);
}

const std::optional<std::string>* secret_field(const Secrets& secrets,
                                               std::string_view name) noexcept
{
    return field_of<const Secrets, const std::optional<std::string>>(secrets, name);
}

std::string not_in_vault(std::string_view name)
{
    return std::string{name} + " is not in the vault";
}

std::vector<std::string> secret_values(const Secrets& secrets, std::size_t room)
{
    std::vector<std::string> values;
    // No growth, here or when the caller adds its `room` values: a
    // reallocation would leave the short values' bytes behind.
    values.reserve(4 + room);
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
    for (const auto& [secret, name] : {std::pair{&secrets.veeam_username, kNameVeeamUsername},
                                       std::pair{&secrets.veeam_password, kNameVeeamPassword}}) {
        if (!secret->has_value() || (*secret)->empty()) {
            throw ConfigError(std::string{name}, not_in_vault(name));
        }
    }
}

std::string_view mask_secret(const std::optional<std::string>& secret) noexcept
{
    return secret && !secret->empty() ? "**** (set)" : "(not set)";
}

} // namespace rp
