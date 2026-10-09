#include <rp/client_check.hpp>

#include "text_util.hpp"

#include <cstddef>

namespace rp {

namespace {

// The most of a product's word a text shows.
constexpr std::size_t kMaxShownWord = 64;

// A product's word as a message shows it: printable ASCII only (anything
// else a space), at most kMaxShownWord bytes, "none" when empty.
std::string shown_word(std::string_view word)
{
    if (word.empty()) {
        return "none";
    }
    std::string out;
    for (const char c : word.substr(0, kMaxShownWord)) {
        out += (c >= 0x20 && c <= 0x7E) ? c : ' ';
    }
    return out;
}

} // namespace

std::string_view to_string(ClientMismatchReason reason) noexcept
{
    switch (reason) {
    case ClientMismatchReason::organization_type:
        return "organization_type";
    case ClientMismatchReason::tenant_id_missing:
        return "tenant_id_missing";
    case ClientMismatchReason::tenant_id:
        return "tenant_id";
    case ClientMismatchReason::region:
        return "region";
    }
    return "unknown";
}

std::optional<ClientMismatch> check_client(const ClientProfile& profile,
                                           const connector::ClientFacts& facts)
{
    if (facts.organization_type != kClientOrganizationType) {
        return ClientMismatch{ClientMismatchReason::organization_type,
                              "the backup's organisation isn't of type " +
                                  std::string{kClientOrganizationType} + " (" +
                                  shown_word(facts.organization_type) + ")"};
    }
    if (facts.tenant_id.empty()) {
        return ClientMismatch{ClientMismatchReason::tenant_id_missing,
                              "the backup's organisation reports no tenant ID"};
    }
    if (!ascii_iequals(facts.tenant_id, profile.graph_tenant_id)) {
        return ClientMismatch{ClientMismatchReason::tenant_id,
                              "the backup's organisation's tenant ID isn't the profile's "
                              "graph_tenant_id"};
    }
    if (facts.region != kClientRegion) {
        return ClientMismatch{ClientMismatchReason::region,
                              "the backup's organisation's region isn't " +
                                  std::string{kClientRegion} + " (" + shown_word(facts.region) +
                                  ")"};
    }
    return std::nullopt;
}

ClientMismatchError::ClientMismatchError(const ClientMismatch& mismatch)
    : std::runtime_error("client mismatch: " + mismatch.text), reason_(mismatch.reason)
{
}

} // namespace rp
