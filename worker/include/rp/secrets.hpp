#pragma once

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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
// The Worker's signing key (W4.3): one line of standard Base64 of an Ed25519
// private key's PKCS#8 DER, the body line of the PEM OpenSSL writes.
// rp::SigningKey::from_base64 (rp/signer.hpp) parses it, and only `rpworker
// test --evidence` and `rpworker signer public-key` do: every other command
// reads it and never looks at it.
inline constexpr std::string_view kEnvSigningKeyBase64 = "RP_SIGNING_KEY_BASE64";

inline constexpr std::array<std::string_view, 5> kSecretEnvVars{
    kEnvVeeamUsername, kEnvVeeamPassword, kEnvGraphCertPfxBase64, kEnvGraphCertPassword,
    kEnvSigningKeyBase64};

// Each field is empty when its variable is unset or set to "". Which ones a
// run needs depends on the Veeam auth mode (W1.0), so loading never fails on
// an unset one.
struct Secrets {
    std::optional<std::string> veeam_username;
    std::optional<std::string> veeam_password;
    std::optional<std::string> graph_cert_pfx_base64;
    std::optional<std::string> graph_cert_password;
    std::optional<std::string> signing_key_base64;
};

// Reads kSecretEnvVars from the process environment, as UTF-8. Throws
// ConfigError (rp/config.hpp), whose key() is the variable's name and whose
// message never contains the value, when a value isn't valid Unicode (an
// unpaired surrogate): it can't be converted without changing the secret. The
// UTF-16 buffer each variable is read into is zeroed before it goes.
Secrets load_secrets_from_env();

// The run's secret values, each as it is: the Veeam password, the Graph PFX's
// Base64, its password and the signing key's text, those that are set and not
// empty, in that order. The user name is no secret. The one list a --record
// recorder and a run folder check what they write against; a run that has
// taken the key's text out of `secrets` (rpworker test --evidence, after the
// recording is opened) adds the text and its shapes for the folder itself.
// Never decodes a value (with --record it runs for commands that never check
// the key), and never throws but for no memory. The caller wipes the list, or
// hands it to a FixtureRecorder, which does. A caller that adds values says
// how many as `room`: the list has that much capacity beyond its own, so
// adding them moves no value (a list that grew would leave the short values'
// bytes behind in the block it left, never wiped).
std::vector<std::string> secret_values(const Secrets& secrets, std::size_t room = 0);

// Throws ConfigError, key() and message naming the variable ("RP_VEEAM_USERNAME
// is not set", then RP_VEEAM_PASSWORD), unless both Veeam secrets are set and
// not empty. The one rule every command and connector that signs in to Veeam
// checks before any Veeam call.
void require_veeam_secrets(const Secrets& secrets);

// What may be printed about a secret: "**** (set)" or "(not set)". Never any
// character of the value, nor its length.
std::string_view mask_secret(const std::optional<std::string>& secret) noexcept;

} // namespace rp
