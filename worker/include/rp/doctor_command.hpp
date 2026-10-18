#pragma once

// `rpworker doctor [--config <path>] [--vault <file>] [--client <profile file>]...
// [--json <file>] [--record <dir>]` (W7.2, docs/decisions.md 2026-10-18): reads
// the machine, the config, the folders, the vault, the signing key, the
// service, the Cloud, the TSA and the clock, Veeam and every organisation's
// certificate, the Worker's Graph certificate and each client named, in the
// entry's order (point 6), and prints one line per check (rp/doctor.hpp),
// then the summary. It changes nothing (point 3): no write but --json's file
// and --record's folder, no grant, no SCM write, no token sent to the Cloud,
// no restore, no explore session, no lock taken. The output and exit codes
// are in docs/worker-config.md ("rpworker doctor").
//
// Every read of the machine is a seam of DoctorEnv, null meaning the real
// one (src/machine_reads.hpp, src/scm.hpp), so the command's branches run on
// fakes: no test touches %ProgramData%, the SCM or LocalMachine\My. Strict
// (100% line).

#include <rp/cert_export.hpp>
#include <rp/doctor.hpp>
#include <rp/graph_client.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>
#include <rp/service.hpp>
#include <rp/timestamper.hpp>
#include <rp/vault.hpp>
#include <rp/veeam_client.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace spdlog {
class logger;
}

namespace rp {

// A certificate of LocalMachine\My as doctor reads it (rp::machine's).
struct DoctorCertificate {
    bool found = false;
    std::optional<std::chrono::system_clock::time_point> not_after;
    std::optional<std::filesystem::path> key_file;
};

struct DoctorEnv {
    // %ProgramData%\RestoreProof, its folders, the config and the vault by
    // default (rp::default_config_path's folder).
    std::function<std::filesystem::path()> data_dir;
    // %ProgramData%, where the machine's key files are.
    std::function<std::filesystem::path()> program_data;
    // %ProgramFiles%\RestoreProof\rpworker.exe: where the installer puts the
    // exe the service must run.
    std::function<std::filesystem::path()> installed_exe;
    // This process's exe.
    std::function<std::filesystem::path()> own_exe;
    std::function<bool()> elevated;
    std::function<std::string()> windows_build;
    // This machine's DNS host name (rp::dns_host_name), for veeam_url.
    std::function<std::optional<std::string>()> host_name;
    std::function<std::chrono::system_clock::time_point()> now;

    std::function<Secrets(const std::filesystem::path& vault)> load_secrets;
    std::function<doctor::Security(const std::filesystem::path&)> read_security;
    std::function<std::optional<std::uint32_t>(const std::filesystem::path&, std::string_view sid,
                                               const std::vector<std::string>& groups)>
        access_for;
    std::function<doctor::LogonFacts()> logon_rights;
    std::function<std::optional<std::uint64_t>(const std::filesystem::path&)> free_bytes;
    std::function<std::string(std::string_view sid)> account_name;
    std::function<DoctorCertificate(std::string_view thumbprint)> machine_certificate;
    // The Worker's exporter of the restore credential, as the pipeline uses it.
    std::function<std::shared_ptr<CertificateExporter>()> exporter;
    // The SCM's two reads (src/scm.hpp); never a write.
    std::function<ScmResult(std::string_view name, ServiceSetup& setup)> read_setup;
    std::function<ScmResult(std::string_view name, ServiceStatus& status)> query_service;

    // The HTTP client for Veeam, the Cloud, the TSA and the reach checks
    // (rp::HttpClient); the command fills ca_file and pinned_cert_sha256.
    std::function<std::unique_ptr<IHttpClient>(const HttpClientOptions&)> make_http;
    // The HTTP client for Entra and Graph (rp::graph::make_graph_http_client).
    std::function<std::unique_ptr<IHttpClient>(std::shared_ptr<spdlog::logger>)> make_graph_http;
    VeeamClientOptions veeam_options;
    graph::GraphClientOptions graph_options;
};

// The real environment: rp::default_config_path's folder, the known folders,
// src/machine_reads.hpp, src/scm.hpp, rp::read_vault, rp::HttpClient and
// rp::graph::make_graph_http_client, a logger of warnings to stderr.
DoctorEnv default_doctor_env();

// The URLs doctor reaches without a client (point 6, check 10).
inline constexpr std::string_view kEntraReachUrl =
    "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
inline constexpr std::string_view kGraphReachUrl = "https://graph.microsoft.com/v1.0/";
// The text whose SHA-256 doctor has the TSA stamp (point 6, check 8).
inline constexpr std::string_view kDoctorStampText = "restoreproof doctor";

// `rpworker doctor ...`; `args` is what follows "doctor". Returns 0 when no
// line is a problem, 5 when one is (rp::doctor::kExitProblem), 64 for a
// command line it doesn't understand (rp::kCliUsage), 1 for --json refused
// before anything is checked ("doctor error: --json <file>: <why>") or an
// unexpected failure ("error: unexpected failure"). With --record, a
// recording that isn't complete turns 0 into 1 (rp::finish_recording). No
// exception escapes.
int run_doctor_command(std::span<const std::string_view> args, std::ostream& out,
                       std::ostream& err, const DoctorEnv& env);

} // namespace rp
