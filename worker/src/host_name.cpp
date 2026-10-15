#include "host_name.hpp"

#include "utf16.hpp"

#include <windows.h>

#include <string>

namespace rp {

std::optional<std::string> dns_host_name()
{
    DWORD size = 0;
    GetComputerNameExW(ComputerNameDnsHostname, nullptr, &size);
    if (size == 0) {
        return std::nullopt;
    }
    std::wstring name(size, L'\0');
    if (!GetComputerNameExW(ComputerNameDnsHostname, name.data(), &size)) {
        return std::nullopt;
    }
    name.resize(size);
    return utf16_to_utf8(name);
}

} // namespace rp
