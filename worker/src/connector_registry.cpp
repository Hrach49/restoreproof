#include <rp/connector_registry.hpp>

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp::connector {

namespace {

// Longer or stranger names aren't quoted back.
constexpr std::size_t kMaxQuotedName = 64;

bool quotable(std::string_view name) noexcept
{
    return name.size() <= kMaxQuotedName &&
           std::ranges::all_of(name, [](char c) { return c >= 0x20 && c <= 0x7E; });
}

std::string unknown_message(std::string_view name, const std::vector<std::string>& known)
{
    std::string list;
    for (const std::string& k : known) {
        list += (list.empty() ? "" : ", ") + k;
    }
    // An empty name is quoted too: "" says plainly what was asked for.
    std::string message = quotable(name) ? "unknown connector \"" + std::string{name} + "\""
                                         : std::string{"unknown connector"};
    return message + " (known: " + (list.empty() ? "none" : list) + ")";
}

} // namespace

UnknownConnectorError::UnknownConnectorError(std::string name,
                                             const std::vector<std::string>& known)
    : std::invalid_argument(unknown_message(name, known)), name_(std::move(name))
{
}

const std::string& UnknownConnectorError::name() const noexcept
{
    return name_;
}

void ConnectorRegistry::add(std::string name, ConnectorFactory factory)
{
    if (name.empty()) {
        throw std::invalid_argument("a connector needs a name");
    }
    if (!factory) {
        throw std::invalid_argument("connector \"" + name + "\" has no factory");
    }
    if (factories_.contains(name)) {
        throw std::invalid_argument("connector \"" + name + "\" is already registered");
    }
    factories_.emplace(std::move(name), std::move(factory));
}

std::unique_ptr<IConnector> ConnectorRegistry::create(std::string_view name, const Config& config,
                                                      const Secrets& secrets,
                                                      const ConnectorOptions& options) const
{
    const auto it = factories_.find(name);
    if (it == factories_.end()) {
        throw UnknownConnectorError(std::string{name}, names());
    }
    std::unique_ptr<IConnector> made = it->second(config, secrets, options);
    if (!made) {
        throw std::logic_error("connector \"" + it->first + "\" made no connector");
    }
    return made;
}

std::vector<std::string> ConnectorRegistry::names() const
{
    std::vector<std::string> out;
    out.reserve(factories_.size());
    for (const auto& entry : factories_) {
        out.push_back(entry.first);
    }
    return out;
}

} // namespace rp::connector
