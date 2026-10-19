// W7.2 (docs/decisions.md 2026-10-18 point 5): doctor's real reads on this
// machine, read-only. Skipped unless RP_LIVE=1; run elevated (doctor's own
// rule): the lab's organisation certificate is found in LocalMachine\My,
// resolved to its key file and exported in memory by the Worker's own
// exporter and discarded; the key file's descriptor is read and Windows'
// access check answers for NT SERVICE\RestoreProof; the logon rights are read
// from the LSA. The second case reads the installed service and fails when
// none is installed: the harness runs it after W7.1's installer
// (docs/api/veeam-lab/w7.2-harness/w72-live.ps1).
//
//   $env:RP_LIVE = '1'; .\worker\build\dev\rptests.exe "[doctor][live]"

#include "graph_live_lab.hpp"

#include "../src/machine_reads.hpp"

#include <rp/cert_export.hpp>
#include <rp/config.hpp>
#include <rp/doctor.hpp>
#include <rp/service.hpp>

#include "../src/scm.hpp"

#include <catch2/catch_test_macros.hpp>

#include <iostream>

namespace {

// The lab organisation's application certificate (lab/tenant.md, W4.12).
constexpr std::string_view kLabThumbprint = "AC3220B58A2B4C438DA13816C2DD1E25D1F783A7";

} // namespace

TEST_CASE("live: doctor's reads of the lab's organisation certificate, its key file and the "
          "logon rights",
          "[doctor][live]")
{
    if (!rp::test::graph_live::live_enabled()) {
        SKIP("set RP_LIVE=1, elevated, on the Veeam server");
    }
    REQUIRE(rp::machine::is_elevated());
    const rp::machine::MachineCertificate cert =
        rp::machine::machine_certificate(kLabThumbprint, rp::program_data_dir());
    REQUIRE(cert.found);
    REQUIRE(cert.key_file);
    std::cout << "key file: " << cert.key_file->string() << '\n';

    rp::ExportedPfx pfx = rp::make_local_machine_cert_exporter()->export_pfx(kLabThumbprint);
    CHECK_FALSE(pfx.pfx_base64.empty());
    pfx.wipe();

    const rp::doctor::Security security = rp::machine::read_security(*cert.key_file);
    REQUIRE(security.readable);
    const std::string sid = *rp::doctor::service_sid(rp::kServiceName);
    const std::optional<std::uint32_t> access =
        rp::machine::access_for(*cert.key_file, sid, rp::doctor::service_token_groups());
    REQUIRE(access);
    std::cout << "NT SERVICE\\RestoreProof on the key file: 0x" << std::hex << *access << std::dec << '\n';

    const rp::doctor::LogonFacts logon = rp::machine::service_logon_rights();
    REQUIRE(logon.allowed);
    std::cout << "Log on as a service: " << logon.allowed->size() << " SID(s), denied "
              << logon.denied.size() << '\n';
}

TEST_CASE("live: doctor's read of the installed RestoreProof service", "[doctor][live][service]")
{
    if (!rp::test::graph_live::live_enabled()) {
        SKIP("set RP_LIVE=1, with the service installed by W7.1's installer");
    }
    rp::ServiceSetup setup;
    const rp::ScmResult read = rp::scm::read_setup(rp::kServiceName, setup);
    // Never a skip: a machine without the service has nothing for this test to read.
    REQUIRE(read.error == 0);
    rp::doctor::Report report;
    rp::doctor::ServiceFacts facts;
    facts.read = read;
    facts.setup = setup;
    facts.query = rp::scm::query_service(rp::kServiceName, facts.status);
    facts.expected_exe = rp::doctor::exe_of_command_line(setup.command_line);
    facts.service_sid = *rp::doctor::service_sid(rp::kServiceName);
    facts.logon = rp::machine::service_logon_rights();
    facts.exe_security = rp::machine::read_security(facts.expected_exe);
    facts.exe_access = rp::machine::access_for(facts.expected_exe, facts.service_sid,
                                               rp::doctor::service_token_groups());
    rp::doctor::check_service(facts, report);
    for (const rp::doctor::Check& check : report.checks()) {
        std::cout << rp::doctor::line_of(check) << '\n';
    }
    CHECK(report.count(rp::doctor::Result::problem) == 0);
}
