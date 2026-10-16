#include "worker_body.hpp"

#include "atomic_file.hpp"
#include "folder_ops.hpp"
#include "file_read.hpp"
#include "heartbeat.hpp"
#include "http_exchange.hpp"
#include "path_utf8.hpp"
#include "run_folder_tail.hpp"
#include "run_pipeline.hpp"
#include "scm.hpp"
#include "service_log_stream.hpp"
#include "text_util.hpp"

#include <rp/cert_export.hpp>
#include <rp/cli.hpp>
#include <rp/cloud_api.hpp>
#include <rp/cloud_command.hpp>
#include <rp/connector_registry.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/outbox_command.hpp>
#include <rp/rfc3161.hpp>
#include <rp/secrets.hpp>
#include <rp/service_jobs.hpp>
#include <rp/service_command.hpp>
#include <rp/service_recovery.hpp>
#include <rp/signer.hpp>
#include <rp/uploader.hpp>
#include <rp/vault.hpp>
#include <rp/version.hpp>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace rp {

namespace {

using std::chrono::milliseconds;

// "<name>.<16 lower-case hex digits>.tmp": what the atomic writer leaves when
// the process ends during a write.
bool is_temp_name(std::string_view name) noexcept
{
    constexpr std::string_view suffix = ".tmp";
    constexpr std::size_t digits = 16;
    if (name.size() <= suffix.size() + digits + 1 || !name.ends_with(suffix)) {
        return false;
    }
    name.remove_suffix(suffix.size());
    const std::string_view hex = name.substr(name.size() - digits);
    return name[name.size() - digits - 1] == '.' &&
           std::ranges::all_of(hex, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

// What the run's folder holds, by the names of what is in it; and, of the
// four files whose word the close would act on, whether the owner passes the
// vault's rule (the runs root has the inherited ACL until W7.1).
FolderContents look_at(const std::filesystem::path& folder)
{
    FolderContents contents;
    std::error_code ec;
    const std::filesystem::file_status status = std::filesystem::symlink_status(folder, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        (!ec && status.type() == std::filesystem::file_type::not_found)) {
        return contents;
    }
    contents.exists = true;
    if (ec || status.type() != std::filesystem::file_type::directory) {
        // Something is there that can't be asked, or isn't a folder: not
        // made, not written into (finding 4 of the W4.8 review).
        contents.list_failed = true;
        return contents;
    }
    for (std::filesystem::directory_iterator entry(folder, ec), end; !ec && entry != end;
         entry.increment(ec)) {
        const std::string name = path_to_utf8(entry->path().filename());
        // Only "owned by somebody else" counts: a file whose owner can't be
        // asked fails at its read.
        const auto seen = [&](std::string_view file, bool& there, bool& untrusted) {
            if (ascii_iequals(name, file)) {
                there = true;
                untrusted = untrusted ||
                            check_trusted_owner(entry->path()) == OwnerTrust::not_trusted;
            }
        };
        seen(kResultFileName, contents.result, contents.result_untrusted);
        seen(kItemsCsvName, contents.items_csv, contents.items_csv_untrusted);
        seen(kSessionLogName, contents.session_log, contents.session_log_untrusted);
        seen(kSignatureFileName, contents.signature, contents.signature_untrusted);
        seen(kTimestampFileName, contents.timestamp, contents.timestamp_untrusted);
        contents.screenshot = contents.screenshot || ascii_iequals(name, kScreenshotName);
        contents.temp_files = contents.temp_files || is_temp_name(name);
    }
    // Not listed whole: nothing is known of the rest (finding 4 of the
    // W4.8 review).
    contents.list_failed = static_cast<bool>(ec);
    return contents;
}

FolderOutcome folder_outcome(const RunFolderOutcome& outcome)
{
    switch (outcome.state) {
    case RunFolderState::complete:
        return {FolderEnd::complete, outcome.word};
    case RunFolderState::queued:
        return {FolderEnd::queued, outcome.word};
    case RunFolderState::none:
    case RunFolderState::incomplete:
        break;
    }
    return {FolderEnd::incomplete, outcome.word};
}

JobFolder job_folder(RunFolderState state) noexcept
{
    switch (state) {
    case RunFolderState::incomplete:
        return JobFolder::incomplete;
    case RunFolderState::complete:
        return JobFolder::complete;
    case RunFolderState::queued:
        return JobFolder::queued;
    case RunFolderState::none:
        break;
    }
    return JobFolder::none;
}

// The record's file calls (rp::RecordFiles).
RecordFiles record_files()
{
    RecordFiles files;
    files.read = [](const std::filesystem::path& file, std::uintmax_t max_bytes) {
        return read_trusted_file(file, max_bytes);
    };
    files.write = [](const std::filesystem::path& file, std::string_view text) {
        // The state folder is the service's own and made by it.
        make_folder(file.parent_path());
        AtomicWriteOptions options;
        options.replace = true;
        return write_file_atomically(file, text, options);
    };
    files.erase = [](const std::filesystem::path& file) {
        std::error_code ec;
        std::filesystem::remove(file, ec);
        return path_kind(file) == PathKind::none;
    };
    files.move_aside = [](const std::filesystem::path& from, const std::filesystem::path& to) {
        // One rename, over an older file of that name.
        std::error_code ec;
        std::filesystem::rename(from, to, ec);
        return !ec;
    };
    return files;
}

// W5.1 point 7: the poll's one request, and the kept document's name.
constexpr std::chrono::milliseconds kJobsPollTimeout{30000};
constexpr std::string_view kKeptJobsName = "jobs.json";

// Everything the env's functions share, kept by each of them.
struct Body {
    std::shared_ptr<ServiceContext> context;
    WorkerBodyOptions options;
    std::filesystem::path runs_root;
    std::filesystem::path outbox_root;
    std::filesystem::path state_dir;
    std::filesystem::path vault;
    // The same as UTF-8, as the pipeline takes its arguments.
    std::string runs_arg;
    std::string outbox_arg;
    std::string vault_arg;
    std::string config_arg;

    // The Cloud's client, from the first flush or heartbeat to the service's
    // end. The uploader is made per flush with the token the vault then holds
    // (W5.1).
    std::unique_ptr<IHttpClient> cloud_http;
    // The hold's one connector and the account it signs in with (point 9).
    std::unique_ptr<connector::IConnector> hold_connector;
    std::string hold_account;
    // W4.11: the connector type the hold's connector is to be made with (the
    // record's); empty = connector::kVeeamM365.
    std::string hold_type;

    const Config& config() const noexcept { return context->config; }
    const std::shared_ptr<spdlog::logger>& logger() const noexcept { return context->logger; }

    bool wait(milliseconds time) const
    {
        return options.wait ? options.wait(time) : context->stop.wait_for(time);
    }

    std::chrono::system_clock::time_point wall_now() const
    {
        return options.wall_now ? options.wall_now() : std::chrono::system_clock::now();
    }

    Outbox outbox() const { return Outbox({outbox_root, options.outbox_files, nullptr}); }

    // <state folder>\done\<run_id>: the mark of a run that was made. An
    // empty file; its being there is all it says.
    std::optional<std::filesystem::path> done_mark(std::string_view run_id) const
    {
        const std::optional<std::filesystem::path> name = path_from_utf8(run_id);
        if (!name) {
            return std::nullopt;
        }
        return state_dir / std::filesystem::path{L"done"} / *name;
    }

    bool run_done(std::string_view run_id) const
    {
        const std::optional<std::filesystem::path> mark = done_mark(run_id);
        return mark && path_kind(*mark) == PathKind::file;
    }

    bool mark_run_done(std::string_view run_id) const
    {
        const std::optional<std::filesystem::path> mark = done_mark(run_id);
        if (!mark || !make_folder(mark->parent_path())) {
            return false;
        }
        AtomicWriteOptions replace;
        replace.replace = true;
        return write_file_atomically(*mark, {}, replace);
    }

    // The pipeline's env with what is the service's (point 5): its logger,
    // its stop as the sleep and the stop check, its run mutex, its vault.
    RestoreCommandEnv pipeline_env() const
    {
        RestoreCommandEnv env =
            options.pipeline_env ? options.pipeline_env() : default_restore_command_env();
        env.default_vault_path = [path = vault] { return path; };
        env.connector_options.logger = logger();
        env.connector_options.sleep = [this](milliseconds time) { wait(time); };
        env.stop_requested = [stop = context] { return stop->stop.requested(); };
        env.connector_options.stop_requested = env.stop_requested;
        env.take_run_lock = [take = options.take_run_lock] { return retaking_abandoned(take); };
        env.outbox_files = options.outbox_files;
        return env;
    }

    // Point 5: rpworker test's pipeline, in process.
    JobRun run_job(const Job& job, const JobCallbacks& calls) const
    {
        // Outside the try: run_pipeline fills it as the run goes, so what
        // escapes keeps what was known (finding 3 of the W4.8 review).
        PipelineReport report;
        try {
            RestoreCommandEnv env = pipeline_env();
            env.on_run_started = calls.on_run_started;
            env.connector_options.on_session_opened = calls.on_session_opened;
            // After a stop nothing is sent, so the record isn't to say a
            // request was.
            env.connector_options.before_restore_request =
                [stop = context, write = calls.before_restore_request] {
                    return !stop->stop.requested() && write();
                };
            PipelineArgs args;
            args.mail = job.sample_mail;
            args.sharepoint = job.sample_sp;
            args.onedrive = job.sample_od;
            args.point = job.restore_point; // `latest` is the pipeline's to read
            args.run_id = job.run_id;
            args.cursor = job.canary_cursor;
            args.config = config_arg;
            args.vault = vault_arg;
            args.evidence = runs_arg;
            args.outbox = outbox_arg;
            args.loaded = &config();
            args.screenshots = job.screenshots_enabled;
            // W4.10: the job's client, never the config's keys. W4.11 (the
            // W4.10 review's finding 7): a job without one is never run on
            // the config's local profile: value() throws, and the job ends
            // before its run line.
            args.client = &job.client.value();
            args.client_id = job.client_id;
            args.connector_type = job.connector_type;
            // Point 12: the run's two streams are the log's.
            LogLineStream out(logger(), spdlog::level::info, job.run_id);
            LogLineStream err(logger(), spdlog::level::warn, job.run_id);
            std::shared_ptr<FixtureRecorder> recorder;
            const int exit =
                run_pipeline(args, out, err, env, recorder, test_presentation(), &report);
            return job_run_of(report, exit);
        } catch (...) {
            return job_run_after_throw(report);
        }
    }

    // The tail of a close (point 7): the key from the vault, held as the
    // pipeline holds it, then the one signing path.
    FolderOutcome finish_folder(
        const std::string& run_id, const std::filesystem::path& folder, bool replace_text_files,
        const std::function<std::optional<std::string>(const Evidence&)>& result) const
    {
        const RestoreCommandEnv env = pipeline_env();
        LogLineStream out(logger(), spdlog::level::info, run_id);
        LogLineStream err(logger(), spdlog::level::warn, run_id);
        Secrets secrets;
        // After `secrets`, so it goes first and wipes the key's text.
        RunSigningKey signing(secrets);
        try {
            secrets = env.load_secrets(vault);
            signing.parse();
        } catch (...) {
            // No vault, or no key in it: nothing can be signed.
            return {FolderEnd::incomplete, "vault"};
        }
        signing.take();
        // No token is never a failure (W4.4): a CA file that can't be used
        // leaves the result signed and not timestamped.
        std::optional<TsaSettings> tsa;
        try {
            tsa = tsa_settings(config());
        } catch (const ConfigError&) {
            err << "timestamp warning: the TSA's CA file can't be used; not timestamped\n";
        }
        RunFolderTail tail;
        tail.folder = folder;
        tail.run_id = run_id;
        tail.screenshots_enabled = config().screenshots_enabled;
        tail.secrets = &secrets;
        tail.signing = &signing;
        tail.tsa = tsa ? &*tsa : nullptr;
        tail.env = &env;
        tail.outbox_root = &outbox_root;
        tail.attachments = [replace_text_files](EvidenceBuilder& builder) {
            return builder.adopt_attachments(replace_text_files);
        };
        tail.result = result;
        RunFolderOutcome outcome;
        finish_run_folder(tail, out, err, exit_code::ok, false, outcome);
        return folder_outcome(outcome);
    }

    // A folder that has its result.json is only queued.
    FolderOutcome queue_folder(const std::string& run_id,
                               const std::filesystem::path& folder) const
    {
        Outbox box = outbox();
        // Why a run got no token was only ever in memory: the manifest says
        // whether it has one.
        const bool stamped =
            path_kind(folder / std::filesystem::path{kTimestampFileName}) == PathKind::file;
        const QueueOutcome queued = box.queue(folder, run_id, wall_now(), stamped, {});
        const bool in_outbox = queued.result == QueueResult::queued ||
                               queued.result == QueueResult::queued_without_manifest;
        if (in_outbox) {
            LogLineStream out(logger(), spdlog::level::info, run_id);
            out << "queued " << path_to_utf8(queued.folder) << '\n';
        }
        return {in_outbox ? FolderEnd::queued : FolderEnd::complete,
                std::string{queue_word(queued.result)}};
    }

    CloseRunOutcome close_run(const RunningRecord& record) const
    {
        const std::optional<std::filesystem::path> name = path_from_utf8(record.run_id);
        if (!name) {
            return {CloseRunState::not_closed, "not_written"};
        }
        // The one folder under the runs root the service touches: the one
        // its record names.
        const std::filesystem::path folder = runs_root / *name;
        CloseRunCalls calls;
        calls.look = [&folder] { return look_at(folder); };
        calls.make_folder = [&folder] { return make_folder(folder); };
        calls.remove_unfinished = [&folder] { return EvidenceBuilder::remove_unfinished(folder); };
        calls.finish = [this, &record, &folder](
                           bool replace_text_files,
                           const std::function<std::optional<std::string>(const Evidence&)>& result) {
            return finish_folder(record.run_id, folder, replace_text_files, result);
        };
        calls.queue = [this, &record, &folder] { return queue_folder(record.run_id, folder); };
        return rp::close_run(record, calls);
    }

    // The hold's connector, made when the hold begins.
    connector::IConnector& hold()
    {
        if (!hold_connector) {
            const RestoreCommandEnv env = pipeline_env();
            Secrets secrets = env.load_secrets(vault);
            {
                // Nothing here signs: the connector's copy of the secrets
                // never holds the key's text.
                RunSigningKey signing(secrets);
                signing.take();
            }
            require_veeam_secrets(secrets);
            hold_account = *secrets.veeam_username;
            hold_connector =
                env.make_connector
                    ? env.make_connector(config(), secrets, env.connector_options)
                    : connector::default_connector_registry().create(
                          hold_type.empty() ? std::string{connector::kVeeamM365} : hold_type,
                          config(), secrets, env.connector_options);
            if (!hold_connector) {
                throw std::logic_error("no connector");
            }
        }
        return *hold_connector;
    }

    SessionsLook own_sessions(std::chrono::system_clock::time_point since)
    {
        try {
            connector::IConnector& source = hold();
            SessionsLook look;
            look.running = source.own_sessions(since);
            look.account = hold_account;
            return look;
        } catch (...) {
            // A look that fails drops the connector; the next makes a new
            // one (a vault read and a sign-in).
            hold_connector.reset();
            throw;
        }
    }

    IHttpClient& cloud()
    {
        if (!cloud_http) {
            std::unique_ptr<IHttpClient> made =
                options.make_cloud_http ? options.make_cloud_http(config(), logger())
                                        : make_cloud_http_client(config(), logger());
            if (!made) {
                throw std::logic_error("no cloud client");
            }
            cloud_http = std::move(made);
        }
        return *cloud_http;
    }

    // W5.1 (docs/decisions.md 2026-10-15, point 6): the vault's
    // cloud_api_token, read at each use, so a token registered or replaced
    // while the service runs is the next request's; empty for none or a vault
    // that can't be read. The other values read with it are wiped.
    std::string api_token() const
    {
        try {
            Secrets secrets = pipeline_env().load_secrets(vault);
            std::string token = secrets.cloud_api_token.value_or(std::string{});
            for (const std::string_view name : kSecretNames) {
                if (std::optional<std::string>* field = secret_field(secrets, name); *field) {
                    secure_wipe(**field);
                }
            }
            return token;
        } catch (const ConfigError&) {
            return {};
        }
    }

    // Point 10: one pass under the flush mutex, the uploader carrying the
    // token the loop hands it (W5.1).
    std::optional<FlushReport> flush(const std::function<bool()>& stop, std::string_view token,
                                     bool token_is_new)
    {
        const std::unique_ptr<RunLock> lock = take_outbox_flush_lock(options.take_flush_lock);
        if (!lock) {
            return std::nullopt;
        }
        CloudUploader uploader(cloud(), config().cloud_url, std::string{token});
        return outbox().flush(uploader, wall_now(), stop, token_is_new);
    }

    // W5.1 point 7: GET <cloud_url>/v1/jobs with the token, sent once, at
    // most kMaxJobsFileBytes of the answer read; what it means is the loop's.
    CloudJobsAnswer poll_jobs(std::string_view token)
    {
        HttpRequest request;
        request.method = HttpMethod::get;
        request.url = cloud_endpoint(config().cloud_url, kJobsPath);
        request.headers["Authorization"] = bearer(token);
        request.headers["Accept"] = "application/json";
        request.timeout = kJobsPollTimeout;
        request.retry_on_status = false;
        request.max_attempts = 1;
        request.max_body_bytes = kMaxJobsFileBytes;
        Exchange answer = exchange(cloud(), request);
        secure_wipe(request.headers["Authorization"]);
        CloudJobsAnswer jobs;
        jobs.word = std::move(answer.word);
        if (answer.response) {
            jobs.status = answer.response->status;
            jobs.kind = cloud_answer_kind(*answer.response);
            jobs.other_value = other_contract_text(*answer.response);
            jobs.body = std::move(answer.response->body);
        }
        return jobs;
    }

    std::filesystem::path kept_jobs_file() const { return state_dir / std::string{kKeptJobsName}; }

    // state\jobs.json written whole, over the one there.
    bool keep_jobs(std::string_view bytes) const
    {
        if (!make_folder(state_dir)) {
            return false;
        }
        AtomicWriteOptions replace;
        replace.replace = true;
        return write_file_atomically(kept_jobs_file(), bytes, replace);
    }

    void drop_jobs() const
    {
        std::error_code ec;
        std::filesystem::remove(kept_jobs_file(), ec);
    }

    // Its age by its last write; nullopt when it isn't there or can't be told.
    // Both times are the file clock's: clock_cast to system_clock goes
    // through utc_clock, which in MSVC loads icu.dll's time-zone data and
    // throws where Windows has none (Server 2016 and 2019; the W5.1 code
    // review's finding 1).
    std::optional<std::chrono::system_clock::duration> kept_jobs_age() const
    {
        std::error_code ec;
        const std::filesystem::file_time_type written =
            std::filesystem::last_write_time(kept_jobs_file(), ec);
        if (ec) {
            return std::nullopt;
        }
        return std::chrono::duration_cast<std::chrono::system_clock::duration>(
            std::filesystem::file_time_type::clock::now() - written);
    }

    // state\worker.json's worker_id, when it reads.
    std::optional<std::string> worker_id() const
    {
        const FileRead file = read_whole_file(state_dir / std::string{kWorkerFileName}, 64u * 1024u);
        if (file.state != FileState::read) {
            return std::nullopt;
        }
        const std::optional<WorkerRecord> record = parse_worker_record(file.bytes);
        return record ? std::optional<std::string>{record->worker_id} : std::nullopt;
    }

    std::string heartbeat(const LoopHeartbeat& beat, std::string_view token)
    {
        Heartbeat heartbeat;
        heartbeat.version = std::string{version()};
        heartbeat.last_error = beat.last_error;
        heartbeat.last_error_at = beat.last_error_at;
        heartbeat.outbox_depth = beat.outbox_depth;
        heartbeat.uptime_s = beat.uptime_s;
        const HeartbeatAnswer answer = send_heartbeat(cloud(), config().cloud_url, token, heartbeat);
        // W5.1 point 5: taken, and the loop says it once.
        return answer.not_cloud ? std::string{kHeartbeatNotCloud} : answer.error;
    }

    // The runs under outbox\, the ones that can't be sent included.
    std::uint64_t outbox_depth() const
    {
        std::uint64_t count = 0;
        std::error_code ec;
        for (std::filesystem::directory_iterator entry(outbox().outbox_folder(), ec), end;
             !ec && entry != end; entry.increment(ec)) {
            std::error_code kind;
            count += entry->is_directory(kind) ? 1 : 0;
        }
        return count;
    }
};

} // namespace

JobRun job_run_of(const PipelineReport& report, int exit_code)
{
    JobRun run;
    run.exit_code = exit_code;
    run.run_line = report.run_line;
    run.status = report.status;
    run.error_code = report.error_code;
    run.replaced_status = report.replaced_status;
    run.replaced_code = report.replaced_code;
    run.folder = job_folder(report.folder);
    run.folder_word = report.folder_word;
    run.restore_may_still_run = report.restore_may_still_run;
    return run;
}

JobRun job_run_after_throw(const PipelineReport& report)
{
    if (!report.run_line) {
        // Nothing was done: no folder, and the record goes.
        JobRun run;
        run.exit_code = exit_code::config;
        return run;
    }
    JobRun run = job_run_of(report, exit_code::config);
    run.restore_may_still_run = true;
    return run;
}

std::unique_ptr<RunLock> retaking_abandoned(const std::function<std::unique_ptr<RunLock>()>& take)
{
    const auto once = [&take] { return take ? take() : try_take_restore_targets_lock(); };
    try {
        return once();
    } catch (const AbandonedRunLock&) {
        return once();
    }
}

ServiceLoopEnv make_worker_loop_env(const std::shared_ptr<ServiceContext>& context,
                                    const WorkerBodyOptions& options)
{
    const std::shared_ptr<Body> body = std::make_shared<Body>();
    body->context = context;
    body->options = options;
    body->runs_root = options.runs_root ? *options.runs_root : default_runs_root();
    body->outbox_root = options.outbox_root ? *options.outbox_root : default_outbox_root();
    body->state_dir = options.state_dir ? *options.state_dir : default_state_dir();
    body->vault = options.vault ? *options.vault : default_vault_path();
    body->runs_arg = path_to_utf8(body->runs_root);
    body->outbox_arg = path_to_utf8(body->outbox_root);
    body->vault_arg = path_to_utf8(body->vault);
    body->config_arg = path_to_utf8(context->config_path);
    ServiceLoopEnv env;
    env.config = context->config;
    if (context->config.jobs_file) {
        env.jobs_file = path_from_utf8(*context->config.jobs_file);
    }
    env.runs_root = body->runs_root;
    env.outbox_root = body->outbox_root;
    env.record_file = body->state_dir / std::filesystem::path{kRunningFileName};
    env.record_files = record_files();
    env.logger = context->logger;

    env.wait = [body](milliseconds time) { return body->wait(time); };
    env.stop_requested = [context] { return context->stop.requested(); };
    env.now = [] { return std::chrono::steady_clock::now(); };
    env.wall_now = [body] { return body->wall_now(); };

    env.read_jobs = [](const std::filesystem::path& file) { return read_jobs(file); };
    // W4.11: the connectors this Worker has, and the hold's by the record.
    env.has_connector = [names = connector::default_connector_registry().names()](
                            std::string_view type) {
        return std::ranges::find(names, type) != names.end();
    };
    env.hold_connector_type = [body](std::string_view type) {
        if (body->hold_connector && body->hold_type != type) {
            body->hold_connector.reset();
        }
        body->hold_type = std::string{type};
    };
    env.outbox_holds = [body](std::string_view run_id) { return body->outbox().holds(run_id); };
    env.run_folder_exists = [body](std::string_view run_id) {
        const std::optional<std::filesystem::path> name = path_from_utf8(run_id);
        return name && path_kind(body->runs_root / *name) != PathKind::none;
    };
    env.run_done = [body](std::string_view run_id) { return body->run_done(run_id); };
    env.mark_run_done = [body](std::string_view run_id) { return body->mark_run_done(run_id); };
    env.outbox_depth = [body] { return body->outbox_depth(); };

    env.run_job = [body](const Job& job, const JobCallbacks& calls) {
        return body->run_job(job, calls);
    };
    env.close_run = [body](const RunningRecord& record) { return body->close_run(record); };

    env.take_run_lock = [body] { return retaking_abandoned(body->options.take_run_lock); };
    env.own_sessions = [body](std::chrono::system_clock::time_point since) {
        return body->own_sessions(since);
    };
    env.end_session = [body](const std::string& id) { body->hold().end_session(id); };
    env.release_hold = [body] { body->hold_connector.reset(); };
    env.clean_targets = [body](const RunningRecord& record) {
        LogLineStream out(body->logger(), spdlog::level::info, record.run_id);
        // W4.10: by the record's profile. A record without one is a job that
        // was no job, which never restored: nothing to clean.
        if (!record.client) {
            return std::string{to_string(TargetsClean::not_started)};
        }
        return std::string{to_string(clean_restore_targets(
            body->config(), *record.client, body->vault, out, body->pipeline_env()))};
    };

    env.flush = [body](const std::function<bool()>& stop, std::string_view token, bool token_is_new) {
        return body->flush(stop, token, token_is_new);
    };
    env.heartbeat = [body](const LoopHeartbeat& beat, std::string_view token) {
        return body->heartbeat(beat, token);
    };
    // W5.1: the token at each use, the Cloud as the job source without a
    // jobs_file, its answer kept in state\jobs.json, the Worker's id.
    env.api_token = [body]() -> std::optional<std::string> {
        std::string token = body->api_token();
        if (token.empty()) {
            return std::nullopt;
        }
        return token;
    };
    env.poll_jobs = [body](std::string_view token) { return body->poll_jobs(token); };
    env.kept_jobs_file = body->kept_jobs_file();
    env.keep_jobs = [body](std::string_view bytes) { return body->keep_jobs(bytes); };
    env.drop_jobs = [body] { body->drop_jobs(); };
    env.kept_jobs_age = [body] { return body->kept_jobs_age(); };
    env.worker_id = body->worker_id();
    return env;
}

ServiceBody make_worker_body(WorkerBodyOptions options)
{
    return [options = std::move(options)](const std::shared_ptr<ServiceContext>& context) {
        ServiceLoop loop(make_worker_loop_env(context, options));
        loop.run();
    };
}

int service_first_start(std::ostream& out, std::ostream& err)
{
    ServiceSetup setup;
    if (scm::read_setup(kServiceName, setup).error != 0) {
        return exit_code::ok;
    }
    std::filesystem::path config;
    std::filesystem::path vault;
    try {
        const std::optional<std::string> arg = service_config_argument(setup.command_line);
        const std::optional<std::filesystem::path> named = arg ? path_from_utf8(*arg) : std::nullopt;
        config = named ? *named : default_config_path();
        vault = default_vault_path();
    } catch (const ConfigError& e) {
        err << "config error: " << e.what() << '\n';
        return exit_code::config;
    }
    return first_start(config, vault, out, err, default_cloud_command_env());
}

} // namespace rp
