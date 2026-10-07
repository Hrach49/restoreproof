#pragma once

// The [live] tests' secrets (W4.5): read from the vault as the Worker reads
// them, never from the environment. RP_LIVE_VAULT names another vault file
// (a path, a switch like RP_LIVE, not a secret); without it the default one,
// %ProgramData%\RestoreProof\vault.bin, which the lab's
// lab/entra/fill-worker-vault.ps1 fills (docs/testing.md, "Live tests").

#include "test_support.hpp"

#include <rp/secrets.hpp>
#include <rp/vault.hpp>

#include <filesystem>
#include <optional>
#include <string>

namespace rp::test {

inline std::filesystem::path live_vault_path()
{
    const std::optional<std::string> given = get_env("RP_LIVE_VAULT");
    if (given && !given->empty()) {
        return std::filesystem::path{widen(*given)};
    }
    return rp::default_vault_path();
}

// Throws rp::VaultError, which fails the test with the vault's own message.
inline rp::Secrets live_secrets()
{
    return rp::read_vault(live_vault_path());
}

} // namespace rp::test
