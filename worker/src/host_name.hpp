#pragma once

// This machine's DNS host name (W5.1, docs/decisions.md 2026-10-15, point 2):
// what `cloud register` sends as the Worker's name without --name. The one
// Win32 call; not strict.

#include <optional>
#include <string>

namespace rp {

// GetComputerNameExW(ComputerNameDnsHostname) in UTF-8, or nullopt when
// Windows can't say or the name isn't UTF-16.
std::optional<std::string> dns_host_name();

} // namespace rp
