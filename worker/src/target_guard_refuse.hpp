#pragma once

// How both layers of the restore-target guard refuse (rp/target_guard.hpp,
// rp/target_guard_veeam.hpp).

#include <rp/target_guard.hpp>

#include <string>

namespace rp {

// Logs "SECURITY: <message>" once, at critical level, through rp::redact, on
// options.logger (or spdlog's default logger; nothing when that is null too),
// then throws connector::SafetyViolation(message). `message` starts with
// "target guard: " and never holds a credential.
[[noreturn]] void refuse_restore(const TargetGuardOptions& options, const std::string& message);

} // namespace rp
