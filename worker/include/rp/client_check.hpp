#pragma once

// The client check's rule (W4.11, docs/decisions.md 2026-10-09 point 3): a
// job's client profile held to the facts the backup product reports about the
// organisation the profile names (connector::ClientFacts, which
// IConnector::client_facts answers). The 2026-09-29 entry's rule, point 4:
// the organisation is of type Office365, its tenant ID (Veeam's msid) is the
// profile's graph_tenant_id, and its region is Worldwide; checked in that
// order, the first fault wins. Every failure is `error client_mismatch`,
// never `fail`: the thing tested couldn't start.
//
// Pure: no call to the backup product or Graph. The two product words live
// here, not in a connector, as the status table holds the backup's own words
// (rp::verification::is_backup_counts): a second connector reports its facts
// and, if its words differ, the rule grows by a row.
//
// Strict (100% line): this decides which client a restore may be made for.

#include <rp/client_profile.hpp>
#include <rp/connector.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace rp {

// The organisation type and region a client's organisation must have.
inline constexpr std::string_view kClientOrganizationType = "Office365";
inline constexpr std::string_view kClientRegion = "Worldwide";

// In the order they are checked.
enum class ClientMismatchReason { organization_type, tenant_id_missing, tenant_id, region };

// "organization_type", "tenant_id_missing", "tenant_id" or "region";
// "unknown" for a value outside the enum.
std::string_view to_string(ClientMismatchReason reason) noexcept;

// Why the profile isn't the organisation's. `text` is one fixed sentence per
// reason, never a tenant ID: "the backup's organisation isn't of type
// Office365 (<type>)", "the backup's organisation reports no tenant ID",
// "the backup's organisation's tenant ID isn't the profile's
// graph_tenant_id", "the backup's organisation's region isn't Worldwide
// (<region>)"; <type> and <region> are the product's own words with control
// characters and non-ASCII bytes as spaces, cut to 64 bytes, "none" when
// empty.
struct ClientMismatch {
    ClientMismatchReason reason = ClientMismatchReason::organization_type;
    std::string text;

    bool operator==(const ClientMismatch&) const = default;
};

// The first fault, in the order of ClientMismatchReason, or nothing when the
// organisation is the profile's: organization_type is kClientOrganizationType
// exactly, tenant_id is there and equals graph_tenant_id ASCII
// case-insensitively (the GUID rules compare so), region is kClientRegion
// exactly. The name isn't compared: the connector found the organisation by
// it. Pure.
std::optional<ClientMismatch> check_client(const ClientProfile& profile,
                                           const connector::ClientFacts& facts);

// What the pipeline throws for a mismatch: a type of its own, which
// verification::stop_reason maps to `client_mismatch`. what() is
// "client mismatch: <text>".
class ClientMismatchError : public std::runtime_error {
public:
    explicit ClientMismatchError(const ClientMismatch& mismatch);

    ClientMismatchReason reason() const noexcept { return reason_; }

private:
    ClientMismatchReason reason_;
};

} // namespace rp
