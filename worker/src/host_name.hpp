#pragma once

// This machine's DNS host name (W5.1, docs/decisions.md 2026-10-15, point 2):
// what `cloud register` sends as the Worker's name without --name; and the
// names `rpworker doctor` holds veeam_url to (W7.2). Win32 calls alone; not
// strict.

#include <optional>
#include <string>
#include <vector>

namespace rp {

// GetComputerNameExW(ComputerNameDnsHostname) in UTF-8, or nullopt when
// Windows can't say or the name isn't UTF-16.
std::optional<std::string> dns_host_name();

// What a URL may call this machine by, for `rpworker doctor`'s veeam_url
// (W7.2 review finding 5): the DNS host name, the fully qualified DNS name,
// the NetBIOS name and every address registered on it (numeric, no IPv6
// zone), each once, those Windows can't give left out.
std::vector<std::string> this_machine_names();

} // namespace rp
