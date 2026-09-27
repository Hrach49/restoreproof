#pragma once

#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace rp {

// Secrets never go in config.json. Until the DPAPI vault arrives (W4.5), they
// are read from these environment variables. This is the one place their
// names are defined.
inline constexpr std::string_view kEnvVeeamUsername = "RP_VEEAM_USERNAME";
inline constexpr std::string_view kEnvVeeamPassword = "RP_VEEAM_PASSWORD";
// The Worker's Graph app signs in with a certificate, not a client secret
// (W2.1): its PFX file as one line of standard Base64, and the PFX's password.
// rp::graph::certificate_from_secrets (rp/client_assertion.hpp) opens them.
inline constexpr std::string_view kEnvGraphCertPfxBase64 = "RP_GRAPH_CERT_PFX_BASE64";
inline constexpr std::string_view kEnvGraphCertPassword = "RP_GRAPH_CERT_PASSWORD";

inline constexpr std::array<std::string_view, 4> kSecretEnvVars{
    kEnvVeeamUsername, kEnvVeeamPassword, kEnvGraphCertPfxBase64, kEnvGraphCertPassword};

// Each field is empty when its variable is unset or set to "". Which ones a
// run needs depends on the Veeam auth mode (W1.0), so loading never fails on
// an unset one.
struct Secrets {
    std::optional<std::string> veeam_username;
    std::optional<std::string> veeam_password;
    std::optional<std::string> graph_cert_pfx_base64;
    std::optional<std::string> graph_cert_password;
};

// Reads kSecretEnvVars from the process environment, as UTF-8. Throws
// ConfigError (rp/config.hpp), whose key() is the variable's name and whose
// message never contains the value, when a value isn't valid Unicode (an
// unpaired surrogate): it can't be converted without changing the secret.
Secrets load_secrets_from_env();

// What may be printed about a secret: "**** (set)" or "(not set)". Never any
// character of the value, nor its length.
std::string_view mask_secret(const std::optional<std::string>& secret) noexcept;

} // namespace rp
