#pragma once

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

// Secrets never go in config.json. Since W4.5 they live in the DPAPI vault
// (rp/vault.hpp, %ProgramData%\RestoreProof\vault.bin) under these seven
// names (five since W4.5, the Cloud's two tokens since W5.1), which are the
// names `rpworker vault set <name>` takes, `vault list` and `config check`
// print and every message uses. This is the one place they are defined. No secret is read from the environment any more.
inline constexpr std::string_view kNameVeeamUsername = "veeam_username";
inline constexpr std::string_view kNameVeeamPassword = "veeam_password";
// The Worker's Graph app signs in with a certificate, not a client secret
// (W2.1): its PFX file as one line of standard Base64, and the PFX's password.
// rp::graph::certificate_from_secrets (rp/client_assertion.hpp) opens them.
inline constexpr std::string_view kNameGraphCertPfxBase64 = "graph_cert_pfx_base64";
inline constexpr std::string_view kNameGraphCertPassword = "graph_cert_password";
// The Worker's signing key (W4.3): one line of standard Base64 of an Ed25519
// private key's PKCS#8 DER, the body line of the PEM OpenSSL writes.
// rp::SigningKey::from_base64 (rp/signer.hpp) parses it, and only `rpworker
// test --evidence` and `rpworker signer public-key` do: every other command
// reads it and never looks at it.
inline constexpr std::string_view kNameSigningKeyBase64 = "signing_key_base64";

// The Cloud's tokens (W5.1, docs/decisions.md 2026-10-15, points 2 and 4):
// the install token the operator sets once (`rpworker vault set
// cloud_install_token`), which `rpworker cloud register` spends and removes,
// and the API token the Cloud answers it with, which the poll, the upload and
// the heartbeat send as `Authorization: Bearer`. Each is 32 random bytes in
// base64url (43 characters), shown once by the Cloud and kept nowhere else.
inline constexpr std::string_view kNameCloudInstallToken = "cloud_install_token";
inline constexpr std::string_view kNameCloudApiToken = "cloud_api_token";

inline constexpr std::array<std::string_view, 7> kSecretNames{
    kNameVeeamUsername,    kNameVeeamPassword, kNameGraphCertPfxBase64, kNameGraphCertPassword,
    kNameSigningKeyBase64, kNameCloudInstallToken, kNameCloudApiToken};

// Each field is empty when its name isn't in the vault. Which ones a run
// needs depends on the command, so reading the vault never fails on an absent
// one.
struct Secrets {
    std::optional<std::string> veeam_username;
    std::optional<std::string> veeam_password;
    std::optional<std::string> graph_cert_pfx_base64;
    std::optional<std::string> graph_cert_password;
    std::optional<std::string> signing_key_base64;
    std::optional<std::string> cloud_install_token;
    std::optional<std::string> cloud_api_token;
};

// The field `name` fills, in kSecretNames' order, or null for a name that
// isn't one of the seven.
std::optional<std::string>* secret_field(Secrets& secrets, std::string_view name) noexcept;
const std::optional<std::string>* secret_field(const Secrets& secrets,
                                               std::string_view name) noexcept;

// "<name> is not in the vault": what every command says for a secret it needs
// and the vault doesn't hold. ConfigError's key() is the name.
std::string not_in_vault(std::string_view name);

// The run's secret values, each as it is: the Veeam password, the Graph PFX's
// Base64, its password, the signing key's text and the Cloud's install and API
// tokens, those that are set and not empty, in that order. The user name is no secret. The one list a --record
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

// Throws ConfigError, key() the name and the message not_in_vault(name)
// ("veeam_username is not in the vault", then veeam_password), unless both
// Veeam secrets are set and not empty. The one rule every command and
// connector that signs in to Veeam checks before any Veeam call.
void require_veeam_secrets(const Secrets& secrets);

// What may be printed about a secret: "**** (set)" or "(not set)". Never any
// character of the value, nor its length.
std::string_view mask_secret(const std::optional<std::string>& secret) noexcept;

} // namespace rp
