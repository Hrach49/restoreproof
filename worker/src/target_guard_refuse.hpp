#pragma once

// How both layers of the restore-target guard refuse (rp/target_guard.hpp,
// rp/target_guard_veeam.hpp).

#include <rp/connector.hpp>
#include <rp/target_guard.hpp>

#include <string>

namespace rp {

// Logs "SECURITY: <message>" once, at critical level, through rp::redact, on
// options.logger (or spdlog's default logger; nothing when that is null too),
// and returns the connector::SafetyViolation(message) the caller throws
// (`throw refusal(...)`, so no function ends in an unreachable epilogue that
// line coverage would count). `message` starts with "target guard: " and never
// holds a credential.
connector::SafetyViolation refusal(const TargetGuardOptions& options, const std::string& message);

} // namespace rp
