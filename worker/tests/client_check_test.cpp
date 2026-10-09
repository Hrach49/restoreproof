// The client check's rule (rp/client_check.hpp; W4.11, docs/decisions.md
// 2026-10-09 point 3): a job's client profile held to the facts the backup
// product reports about the organisation it names. Pure. Failure paths first:
// every mismatch, the order when several are at fault, the texts and what
// they never hold.

#include <rp/client_check.hpp>
#include <rp/client_profile.hpp>
#include <rp/connector.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <optional>
#include <string>
#include <string_view>

using Catch::Matchers::ContainsSubstring;
using rp::check_client;
using rp::ClientMismatch;
using rp::ClientMismatchError;
using rp::ClientMismatchReason;
using rp::ClientProfile;
using rp::connector::ClientFacts;

namespace {

constexpr std::string_view kTenant = "bcd6bd1a-ea42-489d-aa28-2c19a44ad146";

ClientProfile profile()
{
    return {.veeam_org_name = "contoso.onmicrosoft.com",
            .graph_tenant_id = std::string{kTenant},
            .graph_client_id = "22222222-3333-4444-5555-666666666666",
            .test_mailbox = "restoretest@contoso.onmicrosoft.com",
            .test_site_id = "contoso.sharepoint.com,aaaaaaaa-0000-0000-0000-000000000001,"
                            "aaaaaaaa-0000-0000-0000-000000000002",
            .test_library_id = "b!library",
            .test_onedrive_drive_id = "b!onedrive",
            .test_onedrive_folder_id = "01FOLDER"};
}

ClientFacts matching()
{
    return {.name = "contoso.onmicrosoft.com",
            .tenant_id = std::string{kTenant},
            .organization_type = "Office365",
            .region = "Worldwide"};
}

struct Row {
    const char* name;
    ClientFacts facts;
    std::optional<ClientMismatchReason> reason;
    std::string text; // the mismatch's text; "" for none
};

} // namespace

TEST_CASE("client check: each fact held to the profile, the first at fault in order wins",
          "[client_check]")
{
    const Row row = GENERATE(
        Row{"M1 the type isn't Office365",
            ClientFacts{"contoso.onmicrosoft.com", std::string{kTenant}, "Office365Germany",
                        "Worldwide"},
            ClientMismatchReason::organization_type,
            "the backup's organisation isn't of type Office365 (Office365Germany)"},
        Row{"M2 no type", ClientFacts{"contoso.onmicrosoft.com", std::string{kTenant}, "", "Worldwide"},
            ClientMismatchReason::organization_type,
            "the backup's organisation isn't of type Office365 (none)"},
        Row{"M3 the type in another case is another type",
            ClientFacts{"contoso.onmicrosoft.com", std::string{kTenant}, "office365", "Worldwide"},
            ClientMismatchReason::organization_type,
            "the backup's organisation isn't of type Office365 (office365)"},
        Row{"M4 no tenant ID", ClientFacts{"contoso.onmicrosoft.com", "", "Office365", "Worldwide"},
            ClientMismatchReason::tenant_id_missing,
            "the backup's organisation reports no tenant ID"},
        Row{"M5 another tenant",
            ClientFacts{"contoso.onmicrosoft.com", "11111111-2222-3333-4444-555555555555",
                        "Office365", "Worldwide"},
            ClientMismatchReason::tenant_id,
            "the backup's organisation's tenant ID isn't the profile's graph_tenant_id"},
        Row{"M6 the tenant with braces is another tenant",
            ClientFacts{"contoso.onmicrosoft.com", "{" + std::string{kTenant} + "}", "Office365",
                        "Worldwide"},
            ClientMismatchReason::tenant_id,
            "the backup's organisation's tenant ID isn't the profile's graph_tenant_id"},
        Row{"M7 the region isn't Worldwide",
            ClientFacts{"contoso.onmicrosoft.com", std::string{kTenant}, "Office365", "Germany"},
            ClientMismatchReason::region,
            "the backup's organisation's region isn't Worldwide (Germany)"},
        Row{"M8 no region",
            ClientFacts{"contoso.onmicrosoft.com", std::string{kTenant}, "Office365", ""},
            ClientMismatchReason::region,
            "the backup's organisation's region isn't Worldwide (none)"},
        Row{"M9 everything at fault: the type is named first",
            ClientFacts{"", "", "", ""}, ClientMismatchReason::organization_type,
            "the backup's organisation isn't of type Office365 (none)"},
        Row{"M10 tenant and region at fault: the tenant is named first",
            ClientFacts{"contoso.onmicrosoft.com", "11111111-2222-3333-4444-555555555555",
                        "Office365", "China"},
            ClientMismatchReason::tenant_id,
            "the backup's organisation's tenant ID isn't the profile's graph_tenant_id"},
        Row{"M11 a product word with control characters and over 64 bytes is cut",
            ClientFacts{"contoso.onmicrosoft.com", std::string{kTenant},
                        "Office365\tGermany\n" + std::string(80, 'x'), "Worldwide"},
            ClientMismatchReason::organization_type,
            "the backup's organisation isn't of type Office365 (Office365 Germany " +
                std::string(46, 'x') + ")"},
        Row{"K1 every fact as the profile says", matching(), std::nullopt, ""},
        Row{"K2 the tenant ID in upper case is the same tenant",
            ClientFacts{"contoso.onmicrosoft.com", "BCD6BD1A-EA42-489D-AA28-2C19A44AD146",
                        "Office365", "Worldwide"},
            std::nullopt, ""},
        Row{"K3 the organisation's name isn't compared here (the connector found it by name)",
            ClientFacts{"Contoso", std::string{kTenant}, "Office365", "Worldwide"}, std::nullopt,
            ""});
    INFO(row.name);
    const std::optional<ClientMismatch> found = check_client(profile(), row.facts);
    REQUIRE(found.has_value() == row.reason.has_value());
    if (found) {
        CHECK(found->reason == *row.reason);
        CHECK(found->text == row.text);
        // Never a tenant ID: the facts' one nor the profile's.
        CHECK_THAT(found->text, !ContainsSubstring(std::string{kTenant}));
        CHECK_THAT(found->text, !ContainsSubstring("11111111-2222"));
    }
}

TEST_CASE("client check: a profile whose tenant is in upper case matches the same tenant",
          "[client_check]")
{
    ClientProfile upper = profile();
    upper.graph_tenant_id = "BCD6BD1A-EA42-489D-AA28-2C19A44AD146";
    CHECK_FALSE(check_client(upper, matching()).has_value());
}

TEST_CASE("client check: the reasons have one name each", "[client_check]")
{
    CHECK(rp::to_string(ClientMismatchReason::organization_type) == "organization_type");
    CHECK(rp::to_string(ClientMismatchReason::tenant_id_missing) == "tenant_id_missing");
    CHECK(rp::to_string(ClientMismatchReason::tenant_id) == "tenant_id");
    CHECK(rp::to_string(ClientMismatchReason::region) == "region");
    CHECK(rp::to_string(static_cast<ClientMismatchReason>(99)) == "unknown");
}

TEST_CASE("client check: the error carries the reason and says `client mismatch: <text>`",
          "[client_check]")
{
    const ClientMismatch mismatch{ClientMismatchReason::region,
                                  "the backup's organisation's region isn't Worldwide (Germany)"};
    const ClientMismatchError error(mismatch);
    CHECK(error.reason() == ClientMismatchReason::region);
    CHECK(std::string{error.what()} ==
          "client mismatch: the backup's organisation's region isn't Worldwide (Germany)");
    // What the pipeline and the status table read it as: a runtime_error of its own type.
    const std::runtime_error& base = error;
    CHECK_THAT(base.what(), ContainsSubstring("client mismatch"));
}

TEST_CASE("client check: the two product words the rule holds the organisation to",
          "[client_check]")
{
    CHECK(rp::kClientOrganizationType == "Office365");
    CHECK(rp::kClientRegion == "Worldwide");
}
