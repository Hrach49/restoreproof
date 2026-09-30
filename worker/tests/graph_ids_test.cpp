#include "../src/graph_ids.hpp"

#include <rp/config.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kSite = "fe08085d-eb70-42e8-95a6-470189bd98eb";
constexpr std::string_view kWeb = "4ecaf399-cc0e-4d95-b3fe-cd091a09e689";
constexpr std::string_view kList = "ffec069d-65e4-4c3a-9da2-ac086cf9dafa";

} // namespace

// Failure paths first: anything but three UUIDs gives no drive ID.
TEST_CASE("graph_drive_id needs three UUIDs", "[graph-ids]")
{
    const auto [site, web, list] = GENERATE(table<std::string, std::string, std::string>({
        {"", std::string{kWeb}, std::string{kList}},
        {std::string{kSite}, "", std::string{kList}},
        {std::string{kSite}, std::string{kWeb}, ""},
        // One character short, one too many, braces, no dashes, a non-hex digit.
        {"fe08085d-eb70-42e8-95a6-470189bd98e", std::string{kWeb}, std::string{kList}},
        {std::string{kSite}, "4ecaf399-cc0e-4d95-b3fe-cd091a09e6890", std::string{kList}},
        {std::string{kSite}, std::string{kWeb}, "{ffec069d-65e4-4c3a-9da2-ac086cf9dafa}"},
        {"fe08085deb7042e895a6470189bd98eb", std::string{kWeb}, std::string{kList}},
        {std::string{kSite}, std::string{kWeb}, "ffec069d-65e4-4c3a-9da2-ac086cf9dafg"},
        // Veeam's run-together IDs are not one GUID.
        {std::string{kSite} + std::string{kWeb}, std::string{kWeb}, std::string{kList}},
    }));
    CAPTURE(site, web, list);
    CHECK_FALSE(rp::graph_drive_id(site, web, list).has_value());
}

// The three drive IDs Graph gave the lab (lab/seed-manifest.json, lab/tenant.md),
// and the GUIDs Veeam and Graph show for the same library or OneDrive: the
// canary library (list 7eb0f08a, the manifest's list_id), the RestoreTarget
// library (list ffec069d, lab/tenant.md) and alice's OneDrive (Veeam's
// OneDrive ID 6d600fc0…98cfff1a…, and its Documents library).
TEST_CASE("graph_drive_id gives the drive IDs Graph gave the lab", "[graph-ids]")
{
    const auto [site, web, list, drive] =
        GENERATE(table<std::string, std::string, std::string, std::string>({
            {std::string{kSite}, std::string{kWeb}, "7eb0f08a-f57b-418c-8ca6-f2ab81297666",
             "b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omK8LB-e_WMQYym8quBKXZm"},
            {std::string{kSite}, std::string{kWeb}, std::string{kList},
             "b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omdBuz_5GU6TJ2irAhs-dr6"},
            {"6d600fc0-65f8-4811-ad18-096ec5b7e834", "98cfff1a-b404-4438-ae6e-6927a6ccc325",
             "1a9f64df-d9fd-4302-af7a-457d2beff537",
             "b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3"},
        }));
    CAPTURE(list);
    const std::optional<std::string> got = rp::graph_drive_id(site, web, list);
    REQUIRE(got.has_value());
    CHECK(*got == drive);
    // A drive ID parse_config and TargetGuard accept.
    CHECK(rp::is_graph_drive_id(*got));
}

TEST_CASE("graph_drive_id reads the GUIDs in any case", "[graph-ids]")
{
    CHECK(rp::graph_drive_id("FE08085D-EB70-42E8-95A6-470189BD98EB",
                             "4ECAF399-cc0e-4D95-B3FE-CD091A09E689",
                             "FFEC069D-65E4-4C3A-9DA2-AC086CF9DAFA") ==
          std::optional<std::string>{
              "b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omdBuz_5GU6TJ2irAhs-dr6"});
}
