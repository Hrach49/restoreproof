#pragma once

// How both layers of the restore-target guard refuse (rp/target_guard.hpp,
// rp/target_guard_veeam.hpp), and how the Cleaner logs its refusals (W3.4,
// rp/cleaner.hpp).

#include <rp/connector.hpp>
#include <rp/target_guard.hpp>

#include <spdlog/logger.h>

#include <memory>
#include <string>

namespace rp {

// Logs "SECURITY: <message>" once, at critical level, through rp::redact, on
// options.logger (or spdlog's default logger; nothing when that is null too),
// and returns the connector::SafetyViolation(message) the caller throws
// (`throw refusal(...)`, so no function ends in an unreachable epilogue that
// line coverage would count). `message` starts with "target guard: " and never
// holds a credential.
connector::SafetyViolation refusal(const TargetGuardOptions& options, const std::string& message);

// Logs "SECURITY: <message>" once, at critical level, through rp::redact, on
// `logger` (or spdlog's default logger; nothing when that is null too): the
// one form of a security line, refusal()'s and the Cleaner's ("SECURITY:
// cleanup: ...", docs/decisions.md 2026-10-02, W3.4 point 4).
void log_security(const std::shared_ptr<spdlog::logger>& logger, const std::string& message);

} // namespace rp
