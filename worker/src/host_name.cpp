#include "host_name.hpp"

#include "utf16.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <string>

namespace rp {

namespace {

std::optional<std::string> computer_name(COMPUTER_NAME_FORMAT format)
{
    DWORD size = 0;
    GetComputerNameExW(format, nullptr, &size);
    if (size == 0) {
        return std::nullopt;
    }
    std::wstring name(size, L'\0');
    if (!GetComputerNameExW(format, name.data(), &size)) {
        return std::nullopt;
    }
    name.resize(size);
    return utf16_to_utf8(name);
}

void add(std::vector<std::string>& names, std::optional<std::string> name)
{
    if (name && !name->empty() && std::find(names.begin(), names.end(), *name) == names.end()) {
        names.push_back(std::move(*name));
    }
}

// Every address registered on this machine (GetAddrInfoW of the empty name),
// numeric, an IPv6 zone left out.
void add_addresses(std::vector<std::string>& names)
{
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        return;
    }
    ADDRINFOW hints{};
    hints.ai_family = AF_UNSPEC;
    ADDRINFOW* found = nullptr;
    if (GetAddrInfoW(L"", nullptr, &hints, &found) == 0) {
        for (const ADDRINFOW* a = found; a != nullptr; a = a->ai_next) {
            wchar_t host[NI_MAXHOST] = {};
            if (GetNameInfoW(a->ai_addr, static_cast<socklen_t>(a->ai_addrlen), host, NI_MAXHOST, nullptr, 0,
                             NI_NUMERICHOST) == 0) {
                std::wstring text(host);
                text = text.substr(0, text.find(L'%'));
                add(names, utf16_to_utf8(text));
            }
        }
        FreeAddrInfoW(found);
    }
    WSACleanup();
}

} // namespace

std::optional<std::string> dns_host_name()
{
    return computer_name(ComputerNameDnsHostname);
}

std::vector<std::string> this_machine_names()
{
    std::vector<std::string> names;
    add(names, computer_name(ComputerNameDnsHostname));
    add(names, computer_name(ComputerNameDnsFullyQualified));
    add(names, computer_name(ComputerNameNetBIOS));
    add_addresses(names);
    return names;
}

} // namespace rp
