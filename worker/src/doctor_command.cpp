#include <rp/doctor_command.hpp>

#include <rp/cli.hpp>
#include <rp/client_assertion.hpp>
#include <rp/client_check.hpp>
#include <rp/client_profile.hpp>
#include <rp/cloud_api.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/graph_errors.hpp>
#include <rp/graph_targets.hpp>
#include <rp/outbox.hpp>
#include <rp/recording_http_client.hpp>
#include <rp/service_log.hpp>
#include <rp/service_recovery.hpp>
#include <rp/sha256.hpp>
#include <rp/signer.hpp>
#include <rp/version.hpp>

#include "atomic_file.hpp"
#include "command_config.hpp"
#include "file_read.hpp"
#include "http_exchange.hpp"
#include "path_utf8.hpp"
#include "text_table.hpp"
#include "text_util.hpp"
#include "utf16.hpp"
#include "uuid.hpp"

#include <algorithm>
#include <format>
#include <fstream>
#include <ostream>
#include <sstream>
#include <stdexcept>

namespace rp {

namespace {

using std::filesystem::path;

struct Args {
    std::optional<std::string_view> config;
    std::optional<std::string_view> vault;
    std::optional<std::string_view> json;
    std::optional<std::string_view> record;
    std::vector<std::string_view> clients;
};

// `--client` may be given more than once; every other option at most once;
// every value not empty.
std::optional<Args> parse_args(std::span<const std::string_view> args)
{
    Args out;
    for (std::size_t i = 0; i < args.size(); i += 2) {
        if (i + 1 >= args.size() || args[i + 1].empty()) {
            return std::nullopt;
        }
        const std::string_view value = args[i + 1];
        std::optional<std::string_view>* once = nullptr;
        if (args[i] == "--client") {
            out.clients.push_back(value);
            continue;
        }
        if (args[i] == "--config") {
            once = &out.config;
        } else if (args[i] == "--vault") {
            once = &out.vault;
        } else if (args[i] == "--json") {
            once = &out.json;
        } else if (args[i] == "--record") {
            once = &out.record;
        } else {
            return std::nullopt;
        }
        if (once->has_value()) {
            return std::nullopt;
        }
        *once = value;
    }
    return out;
}

// The --json path, as `test --json` checks it: before anything is read.
std::optional<std::string> json_refusal(std::string_view arg, path& file)
{
    const std::string shown = "--json " + table_cell(arg) + ": ";
    const std::optional<path> parsed = path_from_utf8(arg);
    if (!parsed) {
        return shown + "not a UTF-8 path";
    }
    file = *parsed;
    const NewFileCheck check = check_new_file(file);
    if (check == NewFileCheck::ok) {
        return std::nullopt;
    }
    return shown + (check == NewFileCheck::not_a_file_name ? "not a file name"
                    : check == NewFileCheck::exists        ? "the file already exists"
                    : check == NewFileCheck::no_folder     ? "the folder doesn't exist"
                                                           : "a file can't be written there");
}

std::string text_of(const path& p)
{
    return path_to_utf8(p);
}

bool has_value(const std::optional<std::string>& value)
{
    return value && !value->empty();
}

// What a whole run of doctor shares while it reads.
struct Doctor {
    const DoctorEnv& env;
    std::ostream& out;
    doctor::Report report;
    std::size_t printed = 0;
    std::string service_sid;
    path data;
    std::chrono::system_clock::time_point now;
    std::optional<Config> config;
    Secrets secrets;
    bool vault_read = false;
    std::shared_ptr<FixtureRecorder> recorder;
    std::shared_ptr<spdlog::logger> logger;
    std::vector<Organization> organisations;
    bool veeam_read = false;
    std::optional<std::string> worker_id;
    std::optional<std::string> key_id;

    // Prints the lines added since the last call: each area's lines appear as
    // it is read, so a slow network check shows where it is.
    void print()
    {
        for (; printed < report.checks().size(); ++printed) {
            out << doctor::line_of(report.checks()[printed]) << '\n';
        }
        out.flush();
    }

    std::optional<std::uint32_t> access(const path& p) const
    {
        return env.access_for(p, service_sid, doctor::service_token_groups());
    }

    std::unique_ptr<IHttpClient> http(std::string service, std::optional<std::string> ca_file = {},
                                      std::optional<std::string> pin = {}) const
    {
        HttpClientOptions options;
        options.ca_file = std::move(ca_file);
        options.pinned_cert_sha256 = std::move(pin);
        options.logger = logger;
        options.sleep = env.veeam_options.sleep;
        options.jitter = env.veeam_options.jitter;
        return recorded(env.make_http(options), recorder, std::move(service));
    }
};

// --- 1, 2: the machine and the config ------------------------------------------------

std::optional<std::string> service_exe(const DoctorEnv& env)
{
    ServiceSetup setup;
    if (env.read_setup(kServiceName, setup).error != 0) {
        return std::nullopt;
    }
    return doctor::exe_of_command_line(setup.command_line);
}

void read_config(Doctor& d, const path& file)
{
    doctor::ConfigFacts facts;
    facts.file = text_of(file);
    facts.owner = check_trusted_owner(file);
    const doctor::Security security = d.env.read_security(file);
    facts.explicit_entries = std::any_of(security.aces.begin(), security.aces.end(),
                                         [](const doctor::Ace& ace) { return !ace.inherited; });
    try {
        d.config = load_config(file);
        facts.jobs_file_set = has_value(d.config->jobs_file);
        const Config& c = *d.config;
        facts.client_keys_set =
            !(c.veeam_org_name + c.graph_tenant_id + c.graph_client_id + c.test_mailbox +
              c.test_site_id + c.test_library_id + c.test_onedrive_drive_id + c.test_onedrive_folder_id)
                 .empty();
    } catch (const ConfigError& e) {
        facts.load_error = e.what();
    }
    doctor::check_config(facts, d.report);
}

// --- 3: folders, outbox, disk, log -----------------------------------------------------

struct Listing {
    bool listable = false;
    int folders = 0;
    std::optional<std::chrono::seconds> oldest;
};

// A queued run's time: its manifest's queued_at (the outbox rewrites
// manifest.json in the folder at every failed upload, so the folder's own
// time is the last attempt's, never the queueing: W7.2 review finding 2).
// nullopt for a folder with no manifest the outbox would read.
std::optional<std::chrono::system_clock::time_point> queued_at(const path& folder)
{
    // A name that isn't UTF-16 is no run ID, and no manifest names it.
    const std::string run_id = utf16_to_utf8(folder.filename().native()).value_or("");
    const FileRead read = read_whole_file(folder / "manifest.json", 64 * 1024);
    const std::optional<OutboxManifest> manifest =
        read.state == FileState::read ? parse_manifest(read.bytes, run_id) : std::nullopt;
    if (!manifest) {
        return std::nullopt;
    }
    // YYYY-MM-DDTHH:MM:SSZ, the record's time but for its milliseconds.
    return record_time(manifest->queued_at.substr(0, 19) + ".000Z");
}

// The folders under `folder`; with `now`, the age of the oldest queued run
// among them, by its manifest, else by the folder's time.
Listing list_folders(const path& folder,
                     std::optional<std::chrono::system_clock::time_point> now = std::nullopt)
{
    Listing out;
    std::error_code ec;
    std::filesystem::directory_iterator it(folder, ec);
    if (ec) {
        return out;
    }
    out.listable = true;
    const auto file_now = std::filesystem::file_time_type::clock::now();
    for (; it != std::filesystem::directory_iterator(); it.increment(ec)) {
        if (!it->is_directory(ec)) {
            continue;
        }
        ++out.folders;
        if (!now) {
            continue;
        }
        std::optional<std::chrono::seconds> age;
        if (const auto queued = queued_at(it->path())) {
            age = std::chrono::floor<std::chrono::seconds>(*now - *queued);
        } else if (const auto written = it->last_write_time(ec); !ec) {
            age = std::chrono::floor<std::chrono::seconds>(file_now - written);
        }
        if (age && (!out.oldest || *age > *out.oldest)) {
            out.oldest = age;
        }
    }
    return out;
}

std::optional<std::uint64_t> size_of(const path& file)
{
    std::error_code ec;
    const std::uintmax_t size = std::filesystem::file_size(file, ec);
    if (ec) {
        return std::nullopt;
    }
    return size;
}

void read_folders(Doctor& d)
{
    const std::vector<doctor::WantedAcl> wanted = doctor::wanted_folders(d.service_sid);
    std::vector<doctor::FolderFacts> facts;
    for (const doctor::WantedAcl& want : wanted) {
        const path folder = want.path.empty() ? d.data : d.data / want.path;
        doctor::FolderFacts fact{text_of(folder), d.env.read_security(folder), std::nullopt};
        if (fact.security.present && fact.security.readable) {
            fact.service_access = d.access(folder);
        }
        facts.push_back(std::move(fact));
    }
    doctor::check_folders(wanted, facts, d.report);

    const Listing queued = list_folders(d.data / "outbox", d.now);
    const Listing sent = list_folders(d.data / "sent");
    const Listing failed = list_folders(d.data / "failed");
    doctor::check_outbox({text_of(d.data / "failed"), failed.listable, queued.folders, sent.folders,
                          failed.folders, queued.oldest},
                         d.report);
    doctor::check_disk({text_of(d.data), d.env.free_bytes(d.data)}, d.report);

    const path logs = d.data / "logs";
    doctor::LogFacts log{text_of(logs / kLogFileName), size_of(logs / kLogFileName), 0};
    for (std::size_t i = 0; i < LogLimits{}.files; ++i) {
        const path file = i == 0 ? logs / kLogFileName : logs / std::format("worker.{}.log", i);
        log.set_bytes += size_of(file).value_or(0);
    }
    doctor::check_log(log, d.report);
}

// --- 4, 5: the vault and the signing key ---------------------------------------------------

std::vector<std::string> names_in(const Secrets& secrets)
{
    std::vector<std::string> names;
    for (const std::string_view name : kSecretNames) {
        const std::optional<std::string>* field = secret_field(secrets, name);
        if (field != nullptr && has_value(*field)) {
            names.emplace_back(name);
        }
    }
    return names;
}

void read_vault_area(Doctor& d, const path& file)
{
    doctor::VaultFacts facts;
    facts.path = text_of(file);
    facts.service_sid = d.service_sid;
    facts.exe = text_of(d.env.own_exe());
    facts.security = d.env.read_security(file);
    if (facts.security.present && facts.security.readable) {
        facts.service_access = d.access(file);
        for (const doctor::Ace& ace : facts.security.aces) {
            facts.account_names.emplace_back(ace.sid, d.env.account_name(ace.sid));
        }
    }
    try {
        d.secrets = d.env.load_secrets(file);
        d.vault_read = true;
        facts.names = names_in(d.secrets);
    } catch (const ConfigError& e) {
        facts.read_error = e.what();
    }
    doctor::check_vault(facts, d.report);
}

doctor::RecordFacts read_worker_record(const Doctor& d)
{
    const TrustedFile file = read_trusted_file(d.data / "state" / kWorkerFileName, 64 * 1024);
    doctor::RecordFacts facts;
    facts.present = file.state != TrustedRead::absent;
    if (file.state == TrustedRead::read) {
        facts.record = parse_worker_record(file.bytes);
    }
    return facts;
}

void read_signing(Doctor& d, const doctor::RecordFacts& record)
{
    if (!d.vault_read) {
        d.report.skip("signing.key", "signing key: its key_id", "vault.read");
        return;
    }
    doctor::SigningFacts facts;
    facts.in_vault = has_value(d.secrets.signing_key_base64);
    if (facts.in_vault) {
        if (const std::optional<SigningKey> key = SigningKey::from_base64(*d.secrets.signing_key_base64)) {
            facts.key_id = key->key_id();
            d.key_id = key->key_id();
        }
    }
    doctor::check_signing_key(facts, record, d.report);
}

// --- 6: the service --------------------------------------------------------------

void read_service(Doctor& d)
{
    doctor::ServiceFacts facts;
    facts.read = d.env.read_setup(kServiceName, facts.setup);
    facts.query = d.env.query_service(kServiceName, facts.status);
    facts.expected_exe = text_of(d.env.installed_exe());
    facts.service_sid = d.service_sid;
    facts.logon = d.env.logon_rights();
    facts.exe_security = d.env.read_security(d.env.installed_exe());
    if (facts.exe_security.present && facts.exe_security.readable) {
        facts.exe_access = d.access(d.env.installed_exe());
    }
    facts.log_file = text_of(d.data / "logs" / kLogFileName);
    // state\running.json is the service's: NT SERVICE\RestoreProof writes it,
    // so its owner is the service's SID, which read_trusted_file's rule
    // (SYSTEM, Administrators, the calling account) never passes for the
    // operator (W7.2 review finding 1). Doctor takes that owner too.
    const path record_file = d.data / "state" / kRunningFileName;
    std::error_code ec;
    facts.running.present = std::filesystem::exists(record_file, ec) || ec;
    const std::string owner = d.env.read_security(record_file).owner_sid;
    const bool owner_ok = owner == doctor::kSidSystem || owner == doctor::kSidAdministrators ||
                          owner == d.service_sid || check_trusted_owner(record_file) == OwnerTrust::trusted;
    const FileRead running = read_whole_file(record_file, kMaxRecordBytes);
    if (facts.running.present && owner_ok && running.state == FileState::read) {
        if (const std::optional<RunningRecord> record = parse_record(running.bytes)) {
            facts.running.run_id = record->run_id;
            if (const auto taken = record_time(record->taken_at)) {
                facts.running.age = std::chrono::floor<std::chrono::seconds>(d.now - *taken);
            }
        }
    }
    doctor::check_service(facts, d.report);
}

// --- 7, 8: the Cloud, the TSA and the clock ---------------------------------------------

void read_cloud(Doctor& d, const doctor::RecordFacts& record)
{
    if (!d.config) {
        d.report.skip("cloud", "cloud: the registration and /v1/version", "config.load");
        return;
    }
    doctor::CloudFacts facts;
    facts.cloud_url = d.config->cloud_url;
    facts.record = record;
    if (record.record) {
        d.worker_id = record.record->worker_id;
    }
    const std::unique_ptr<IHttpClient> http = d.http("cloud", d.config->cloud_ca_file);
    HttpRequest request;
    request.url = d.config->cloud_url;
    while (request.url.ends_with('/')) {
        request.url.pop_back();
    }
    request.url += "/v1/version";
    request.max_attempts = 1;
    request.max_body_bytes = 64 * 1024;
    const Exchange answer = exchange(*http, request);
    facts.version.answered = answer.response.has_value();
    facts.version.failure = answer.word;
    if (answer.response) {
        facts.version.status = answer.response->status;
        facts.version.kind = cloud_answer_kind(*answer.response);
        facts.version.body = answer.response->body;
    }
    doctor::check_cloud(facts, d.report);
}

void read_tsa(Doctor& d)
{
    if (!d.config) {
        d.report.skip("tsa", "tsa and clock: a token's time", "config.load");
        return;
    }
    doctor::TsaFacts facts;
    facts.url = d.config->tsa_url.value_or(std::string(kDefaultTsaUrl));
    // The config's load already read tsa_ca_file and found a certificate in it;
    // a file gone since is an empty root, and the token "tsa_untrusted".
    std::string ca = std::string(default_tsa_ca_pem());
    if (d.config->tsa_ca_file) {
        std::ifstream file(*path_from_utf8(*d.config->tsa_ca_file), std::ios::binary);
        std::ostringstream text;
        text << file.rdbuf();
        ca = text.str();
    }
    const std::unique_ptr<IHttpClient> http = d.http("tsa");
    int asked = 0;
    TimestamperOptions options;
    options.url = facts.url;
    options.ca_pem = ca;
    options.http = http.get();
    options.stop_requested = [&asked] { return asked++ > 0; };
    const Timestamper timestamper(std::move(options));
    const TimestampOutcome outcome = timestamper.stamp(sha256_bytes(kDoctorStampText));
    facts.stamped = outcome.stamped();
    facts.error = std::string(outcome.error);
    facts.gen_time = outcome.gen_time;
    // This machine's clock as the token came back, never doctor's start: the
    // reads before it (a Cloud that times out, a slow Veeam) are no skew
    // (W7.2 review finding 6).
    facts.now = std::chrono::duration_cast<std::chrono::seconds>(d.env.now().time_since_epoch()).count();
    doctor::check_tsa(facts, d.report);
}

// --- 9: Veeam ------------------------------------------------------------------

// Whether `url`'s host is the loopback or one of `names` (this machine's
// names and addresses, rp::this_machine_names), any case.
bool is_this_machine(std::string_view url, const std::vector<std::string>& names)
{
    std::string_view host = url;
    if (const std::size_t scheme = host.find("://"); scheme != std::string_view::npos) {
        host.remove_prefix(scheme + 3);
    }
    host = host.substr(0, host.find('/'));
    if (host.starts_with('[')) {
        host = host.substr(1, host.find(']') - 1);
    } else {
        host = host.substr(0, host.find(':'));
    }
    const std::string lower = ascii_lower(host);
    if (lower == "localhost" || lower == "::1" || lower.starts_with("127.")) {
        return true;
    }
    return std::any_of(names.begin(), names.end(), [&](const std::string& name) { return ascii_iequals(name, host); });
}

doctor::CertificateFacts read_certificate(const Doctor& d, const std::string& thumbprint)
{
    doctor::CertificateFacts facts;
    facts.thumbprint = thumbprint;
    try {
        ExportedPfx pfx = d.env.exporter()->export_pfx(thumbprint);
        pfx.wipe();
    } catch (const CertExportError& e) {
        facts.export_failure = e.reason();
        facts.export_message = e.what();
    }
    const DoctorCertificate cert = d.env.machine_certificate(thumbprint);
    facts.not_after = cert.not_after;
    if (cert.key_file) {
        facts.key_file = text_of(*cert.key_file);
        facts.service_access = d.access(*cert.key_file);
    }
    return facts;
}

void read_veeam(Doctor& d)
{
    if (!d.config) {
        d.report.skip("veeam", "veeam: the login, the organisations and their certificates", "config.load");
        return;
    }
    doctor::VeeamFacts facts;
    facts.url = d.config->veeam_url;
    facts.url_local = is_this_machine(d.config->veeam_url, d.env.machine_names());
    facts.rest_query = d.env.query_service(doctor::kVeeamRestService, facts.rest_status);
    facts.service_sid = d.service_sid;
    facts.now = d.now;
    // The login needs the vault's two values: without them it is a skip
    // naming the check that already said so (W7.2 review finding 7).
    if (!d.vault_read || !has_value(d.secrets.veeam_username) || !has_value(d.secrets.veeam_password)) {
        facts.login_needs = !d.vault_read                           ? "vault.read"
                            : !has_value(d.secrets.veeam_username) ? "vault.veeam_username"
                                                                   : "vault.veeam_password";
        doctor::check_veeam(facts, d.report);
        return;
    }
    const std::unique_ptr<IHttpClient> http =
        d.http("veeam", d.config->veeam_ca_file, d.config->veeam_cert_sha256);
    VeeamClientOptions options = d.env.veeam_options;
    options.logger = d.logger;
    VeeamClient client(*http, d.config->veeam_url, *d.secrets.veeam_username,
                       *d.secrets.veeam_password, options);
    try {
        client.login();
        d.organisations = client.list_organizations();
        for (const Organization& org : d.organisations) {
            doctor::OrganisationFacts of;
            of.name = org.name;
            // VeeamClient refuses an ID that isn't a UUID with
            // std::invalid_argument, as find_organization says: nothing more
            // is asked of such an organisation (W7.2 review finding 9).
            of.id_ok = is_uuid(org.id);
            if (!of.id_ok) {
                facts.organisations.push_back(std::move(of));
                continue;
            }
            for (const RestorePoint& point : client.list_restore_points(org.id)) {
                if (!of.newest_point || point.backup_time > *of.newest_point) {
                    of.newest_point = point.backup_time;
                }
            }
            std::vector<std::string> thumbprints;
            for (const std::optional<OrganizationApp>* app : {&org.exchange_app, &org.sharepoint_app}) {
                if (*app && std::find(thumbprints.begin(), thumbprints.end(),
                                      ascii_upper((*app)->certificate_thumbprint)) == thumbprints.end()) {
                    thumbprints.push_back(ascii_upper((*app)->certificate_thumbprint));
                }
            }
            for (const std::string& thumbprint : thumbprints) {
                of.certificates.push_back(read_certificate(d, thumbprint));
            }
            facts.organisations.push_back(std::move(of));
        }
        d.veeam_read = true;
    } catch (const VeeamError& e) {
        facts.login_error = std::string("veeam error: ") + e.what();
        facts.organisations.clear();
    }
    client.logout();
    doctor::check_veeam(facts, d.report);
}

// --- 10, 11: Graph and the clients ----------------------------------------------------

std::string reach(Doctor& d, std::string_view url)
{
    const std::unique_ptr<IHttpClient> http = d.http("reach");
    HttpRequest request;
    request.url = std::string(url);
    request.max_attempts = 1;
    request.max_body_bytes = 64 * 1024;
    return exchange(*http, request).word;
}

std::optional<graph::ClientCertificate> certificate(const Doctor& d, std::string* error)
{
    try {
        return graph::certificate_from_secrets(d.secrets, d.now, d.logger);
    } catch (const ConfigError& e) {
        if (error != nullptr) {
            *error = e.what();
        }
    }
    return std::nullopt;
}

bool read_graph(Doctor& d, bool clients_named)
{
    if (!d.vault_read) {
        d.report.skip("graph", "graph: the Worker's certificate", "vault.read");
        return false;
    }
    doctor::GraphFacts facts;
    facts.now = d.now;
    facts.exe = text_of(d.env.own_exe());
    facts.clients_named = clients_named;
    std::string error;
    if (const std::optional<graph::ClientCertificate> cert = certificate(d, &error)) {
        facts.thumbprint = cert->sha1_thumbprint();
        facts.not_after = cert->not_after();
    } else {
        facts.certificate_error = error;
    }
    if (!clients_named && !facts.certificate_error) {
        for (const std::string_view url : {kEntraReachUrl, kGraphReachUrl}) {
            std::string_view host = url.substr(8);
            host = host.substr(0, host.find('/'));
            facts.reach.emplace_back(std::string(host), reach(d, url));
        }
    }
    return doctor::check_graph(facts, d.report);
}

std::string graph_error(const graph::GraphError& e)
{
    return std::string("graph error: ") + e.what();
}

doctor::TargetRead read_target(const std::function<std::size_t()>& list)
{
    doctor::TargetRead read;
    try {
        read = {true, list(), {}};
    } catch (const graph::GraphError& e) {
        read = {false, 0, graph_error(e)};
    }
    return read;
}

void read_client(Doctor& d, int number, std::string_view file_arg, bool graph_ready)
{
    doctor::ClientFacts facts;
    facts.number = number;
    facts.file = std::string(file_arg);
    try {
        const std::optional<path> file = path_from_utf8(file_arg);
        if (!file) {
            throw ConfigError("--client", "--client " + table_cell(file_arg) + ": not a UTF-8 path");
        }
        facts.profile = read_client_profile_file(*file);
    } catch (const ConfigError& e) {
        facts.profile_error = e.what();
    }
    if (facts.profile_error) {
        doctor::check_client(facts, graph_ready, d.report);
        return;
    }
    if (d.veeam_read) {
        // As the pipeline finds it (veeam_explore::find_organization): by
        // name whatever the case of A-Z, and one only.
        const std::string name = table_cell(facts.profile.veeam_org_name);
        const auto named = [&](const Organization& o) { return ascii_iequals(o.name, facts.profile.veeam_org_name); };
        const auto org = std::find_if(d.organisations.begin(), d.organisations.end(), named);
        const auto matches = std::count_if(d.organisations.begin(), d.organisations.end(), named);
        if (org == d.organisations.end()) {
            facts.veeam_check = "Veeam has no organisation " + name + " (veeam_org_name)";
        } else if (matches > 1) {
            facts.veeam_check = std::format("{} organisations in Veeam are named {} (veeam_org_name)", matches, name);
        } else if (!is_uuid(org->id)) {
            facts.veeam_check = "Veeam's ID for the organisation " + name + " isn't a UUID";
        } else {
            const std::optional<ClientMismatch> mismatch =
                check_client(facts.profile, {org->name, org->msid, org->type, org->region});
            facts.veeam_check = mismatch ? "client_mismatch: " + mismatch->text : std::string();
        }
    }
    if (graph_ready) {
        std::optional<graph::ClientCertificate> cert = certificate(d, nullptr);
        graph::GraphClientOptions options = d.env.graph_options;
        options.logger = d.logger;
        const std::unique_ptr<IHttpClient> http = recorded(d.env.make_graph_http(d.logger), d.recorder, "graph");
        // A client with no token that nothing uses: doctor lists, it downloads nothing.
        const std::unique_ptr<IHttpClient> downloads = d.http("download");
        graph::GraphClient client(*http, facts.profile.graph_tenant_id, facts.profile.graph_client_id,
                                  std::move(*cert), options);
        try {
            facts.roles = client.token_roles();
        } catch (const graph::GraphError& e) {
            facts.token_error = graph_error(e);
        }
        if (!facts.token_error) {
            graph::TargetReaderOptions reader_options;
            reader_options.logger = d.logger;
            reader_options.hash_items = false;
            graph::TargetReader reader(client, *downloads,
                                       connector::RestoreTargets::from_profile(facts.profile), reader_options);
            facts.mail = read_target([&] { return reader.list_mail().size(); });
            facts.library = read_target([&] { return reader.list_sharepoint().size(); });
            facts.folder = read_target([&] { return reader.list_onedrive().size(); });
        }
    }
    doctor::check_client(facts, graph_ready, d.report);
}

// --- the command -------------------------------------------------------------------

int run(const Args& args, std::ostream& out, std::ostream& err, const DoctorEnv& env,
        std::shared_ptr<FixtureRecorder>& recorder)
{
    path json_file;
    if (args.json) {
        if (const std::optional<std::string> refusal = json_refusal(*args.json, json_file)) {
            err << "doctor error: " << *refusal << '\n';
            return exit_code::config;
        }
    }
    Doctor d{env, out};
    // The vault's values are wiped however doctor leaves: the --json file
    // refused, or an exception on its way to run_doctor_command (W7.2 review
    // finding 9).
    struct Wipe {
        Secrets& secrets;
        ~Wipe() { wipe_secrets(secrets, ""); }
    } const wipe{d.secrets};
    d.service_sid = *doctor::service_sid(kServiceName);
    d.data = env.data_dir();
    d.now = env.now();
    d.logger = make_command_logger();

    const bool elevated = env.elevated();
    const bool go = doctor::check_doctor({elevated, std::string(version()), text_of(env.own_exe()),
                                          elevated ? service_exe(env) : std::nullopt},
                                         d.report);
    d.print();
    if (go) {
        read_config(d, command_config_path(args.config, [&] { return d.data / "config.json"; }));
        d.print();
        read_folders(d);
        d.print();
        read_vault_area(d, command_vault_path(args.vault, [&] { return d.data / kVaultFileName; }));
        d.print();
        recorder = open_recording(args.record, "doctor", d.secrets);
        d.recorder = recorder;
        const doctor::RecordFacts record = read_worker_record(d);
        read_signing(d, record);
        d.print();
        read_service(d);
        d.print();
        read_cloud(d, record);
        d.print();
        read_tsa(d);
        d.print();
        read_veeam(d);
        d.print();
        const bool graph_ready = read_graph(d, !args.clients.empty());
        d.print();
        for (std::size_t i = 0; i < args.clients.size(); ++i) {
            read_client(d, static_cast<int>(i) + 1, args.clients[i], graph_ready);
            d.print();
        }
    }
    out << d.report.summary_line() << '\n';
    if (args.json) {
        const doctor::JsonFacts facts{std::string(version()), env.windows_build(),
                                      std::format("{:%Y-%m-%dT%H:%M:%SZ}",
                                                  std::chrono::floor<std::chrono::seconds>(d.now)),
                                      elevated, d.worker_id.value_or(""), d.key_id.value_or("")};
        if (!write_file_atomically(json_file, doctor::json_text(d.report, facts))) {
            err << "doctor error: --json " << text_of(json_file) << ": couldn't be written\n";
            return exit_code::config;
        }
    }
    out.flush();
    return d.report.exit_code();
}

} // namespace

int run_doctor_command(std::span<const std::string_view> args, std::ostream& out, std::ostream& err,
                       const DoctorEnv& env)
{
    const std::optional<Args> parsed = parse_args(args);
    if (!parsed) {
        err << kCliUsage;
        return exit_code::usage;
    }
    std::shared_ptr<FixtureRecorder> recorder;
    int code = exit_code::config;
    std::string failure;
    try {
        code = run(*parsed, out, err, env, recorder);
    } catch (const ConfigError& e) {
        failure = std::string("doctor error: ") + e.what();
    } catch (...) {
        failure = "error: unexpected failure";
    }
    if (!failure.empty()) {
        err << failure << '\n';
        return exit_code::config;
    }
    return finish_recording(recorder.get(), out, err, code);
}

} // namespace rp
