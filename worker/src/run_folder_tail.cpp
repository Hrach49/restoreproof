#include "run_folder_tail.hpp"

#include <rp/cert_export.hpp>
#include <rp/cli.hpp>
#include <rp/http_client.hpp>
#include <rp/outbox.hpp>
#include <rp/rfc3161.hpp>
#include <rp/timestamper.hpp>

#include "command_config.hpp"
#include "file_read.hpp"
#include "path_utf8.hpp"
#include "text_table.hpp"

#include <chrono>
#include <cstdint>
#include <ostream>
#include <span>
#include <thread>
#include <utility>

namespace rp {

namespace {

// The TSA's time and the Worker's clock further apart than this is said
// (W7.2's threshold), never refused.
constexpr std::chrono::seconds kClockSkewWarning{120};

// A CA file larger than this isn't one.
constexpr std::uintmax_t kMaxTsaCaFileBytes = 64u * 1024u;

} // namespace

std::string_view queue_word(QueueResult result) noexcept
{
    switch (result) {
    case QueueResult::queued:
        break;
    case QueueResult::queued_without_manifest:
        return "manifest_not_written";
    case QueueResult::not_complete:
        return "not_complete";
    case QueueResult::already_queued:
        return "already_queued";
    case QueueResult::already_sent:
        return "already_sent";
    case QueueResult::no_outbox_folder:
        return "no_outbox_folder";
    case QueueResult::not_same_volume:
        return "not_same_volume";
    case QueueResult::not_moved:
        return "not_moved";
    }
    return {};
}

RunSigningKey::~RunSigningKey()
{
    take();
    secure_wipe(text_);
}

void RunSigningKey::parse()
{
    const std::string name{kNameSigningKeyBase64};
    const std::optional<std::string>& text = secrets_.signing_key_base64;
    if (!text || text->empty()) {
        throw ConfigError(name, not_in_vault(name) + "; --evidence signs the result");
    }
    key_ = SigningKey::from_base64(*text);
    if (!key_) {
        throw ConfigError(name, name + " is not an Ed25519 private key (Base64 of PKCS#8 DER)");
    }
}

void RunSigningKey::take() noexcept
{
    if (secrets_.signing_key_base64) {
        text_.swap(*secrets_.signing_key_base64);
        secure_wipe(*secrets_.signing_key_base64);
        secrets_.signing_key_base64.reset();
    }
}

TsaSettings tsa_settings(const Config& config)
{
    constexpr std::string_view key = "tsa_ca_file";
    TsaSettings out;
    out.url = config.tsa_url.value_or(std::string{kDefaultTsaUrl});
    out.ca_pem = std::string{default_tsa_ca_pem()};
    if (config.tsa_ca_file) {
        const std::optional<std::filesystem::path> path = path_from_utf8(*config.tsa_ca_file);
        FileRead read;
        if (path) {
            read = read_whole_file(*path, kMaxTsaCaFileBytes);
        }
        if (read.state != FileState::read) {
            throw ConfigError(std::string{key},
                              "config key \"tsa_ca_file\" names a file that can't be read");
        }
        out.ca_pem = std::move(read.bytes);
    }
    if (openssl_rfc3161().certificates_in(out.ca_pem) == 0) {
        throw ConfigError(std::string{key},
                          "config key \"tsa_ca_file\" names a file that holds no "
                          "certificate (PEM)");
    }
    return out;
}

int finish_run_folder(const RunFolderTail& tail, std::ostream& out, std::ostream& err, int code,
                      bool output_lost, RunFolderOutcome& outcome) noexcept
{
    const auto failed = [&](std::string_view what, std::string_view why, std::string_view word) {
        err << "evidence error: " << what << ": " << why << '\n';
        code = code == exit_code::ok ? exit_code::config : code;
        outcome.word = word;
    };
    // Until result.json is written the folder is short of it, whatever
    // happens here.
    outcome = {RunFolderState::incomplete, "not_written"};
    try {
        const RestoreCommandEnv& env = *tail.env;
        const std::string shown = table_cell(path_to_utf8(tail.folder));
        EvidenceOptions options;
        options.screenshots_enabled = tail.screenshots_enabled;
        options.capture = env.capture_screenshot;
        options.write_file = env.write_evidence_file;
        // The run's secret values: the Secrets', the signing key's text,
        // which is no longer among them, and the other shapes the key
        // could leak in. The builder wipes its copy when it goes. Room
        // for the three added here, so the list never grows.
        options.secrets = secret_values(*tail.secrets, 3);
        if (!tail.signing->text().empty()) {
            options.secrets.push_back(tail.signing->text());
        }
        if (const SigningKey* key = tail.signing->key()) {
            options.secrets.insert(options.secrets.end(), key->secret_shapes().begin(),
                                   key->secret_shapes().end());
            options.sign = [&env, key](std::string_view canonical) {
                return env.sign_result ? env.sign_result(canonical, *key)
                                       : Signer::sign(canonical, *key);
            };
        }
        options.logger = env.connector_options.logger ? env.connector_options.logger
                                                      : make_command_logger();
        // W4.4: the TSA, asked once the result is signed. Its client is
        // made only now; with --record its exchanges are the recording's
        // "tsa" folder, both bodies as Base64.
        std::unique_ptr<IHttpClient> tsa_http;
        std::optional<Timestamper> timestamper;
        if (tail.tsa && options.sign) {
            HttpClientOptions http_options;
            http_options.logger = options.logger;
            tsa_http = recorded(env.make_tsa_http ? env.make_tsa_http()
                                                  : std::make_unique<HttpClient>(http_options),
                                tail.recorder, "tsa", RecordedBody::base64);
            TimestamperOptions stamp_options;
            stamp_options.url = tail.tsa->url;
            stamp_options.ca_pem = tail.tsa->ca_pem;
            stamp_options.http = tsa_http.get();
            stamp_options.nonce = env.timestamp_nonce;
            stamp_options.sleep = env.connector_options.sleep;
            if (!stamp_options.sleep) {
                stamp_options.sleep = [](std::chrono::milliseconds wait) {
                    std::this_thread::sleep_for(wait);
                };
            }
            // W4.8 point 13: after a stop no further attempt is made.
            stamp_options.stop_requested = env.stop_requested;
            stamp_options.logger = options.logger;
            timestamper.emplace(std::move(stamp_options));
            options.timestamp = [&timestamper](
                                    std::span<const unsigned char, kSha256Bytes> digest) {
                return timestamper->stamp(digest);
            };
        }
        EvidenceBuilder builder(tail.folder, std::move(options));
        const EvidenceBuilder::Written written = tail.attachments(builder);
        for (const EvidenceError& error : written.errors) {
            failed(shown + '\\' + error.file, "could not be written", "not_written");
        }
        if (!written.evidence) {
            return code;
        }
        const std::optional<std::string> text = tail.result(*written.evidence);
        if (!text) {
            failed(shown,
                   "the result isn't valid restoreproof.result.v1; no result.json was written",
                   "invalid");
            return code;
        }
        SignedResult signature;
        TimestampOutcome timestamp;
        if (const std::optional<EvidenceError> error =
                builder.write_result(*written.evidence, *text, &signature, &timestamp)) {
            if (error->cause == EvidenceFailure::holds_secret) {
                failed(shown, "the result holds a secret value; no result.json was written",
                       "holds_secret");
            } else if (error->cause == EvidenceFailure::not_signed) {
                failed(shown, "the result couldn't be signed; no result.json was written",
                       "not_signed");
            } else if (error->cause == EvidenceFailure::changed) {
                failed(shown + '\\' + error->file, "changed after it was hashed", "changed");
            } else {
                failed(shown + '\\' + error->file, "could not be written", "not_written");
            }
            return code;
        }
        outcome = {RunFolderState::complete, {}};
        // W4.4: no token is a warning, never the run's failure: the
        // status, the exit code and the folder stay. Nor is a clock that
        // disagrees with the TSA's one: the token is the better clock.
        if (!timestamp.stamped() && !timestamp.error.empty()) {
            err << "timestamp warning: " << shown << ": not timestamped: " << timestamp.error
                << " after " << timestamp.attempts << " attempt(s)\n";
        } else if (timestamp.stamped()) {
            const auto now = env.connector_options.wall_now ? env.connector_options.wall_now()
                                                            : std::chrono::system_clock::now();
            const std::int64_t apart =
                std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() -
                timestamp.gen_time;
            if (apart > kClockSkewWarning.count() || apart < -kClockSkewWarning.count()) {
                err << "timestamp warning: the TSA's time and this machine's clock differ by "
                    << (apart < 0 ? -apart : apart) << " s\n";
            }
        }
        // The signature's line (W4.3), the timestamp's (W4.4) and the
        // folder's, all only now that result.json is written, the
        // folder's last. Lost, they change nothing: the files are written
        // (W3.6 review point 4).
        if (!output_lost) {
            try {
                out << "signed " << signature.bundle_sha256 << " key " << signature.key_id << '\n';
                if (timestamp.stamped()) {
                    out << "timestamped " << timestamp_time_text(timestamp.gen_time) << '\n';
                }
                out << "evidence " << shown << ": " << kResultFileName << ", "
                    << kSignatureFileName << ", "
                    << (timestamp.stamped() ? kTimestampFileName : std::string_view{})
                    << (timestamp.stamped() ? ", " : "") << kItemsCsvName << ", "
                    << kSessionLogName << (written.evidence->screenshot.captured ? ", " : "")
                    << (written.evidence->screenshot.captured ? kScreenshotName : "") << '\n';
                out.flush();
            } catch (...) {
            }
        }
        // W4.6: the folder is complete and its lines are out: queued by
        // one rename, then its manifest, the only file written in it from
        // here on. A folder that can't be queued stays where and as it
        // is; the status stays too.
        if (tail.outbox_root) {
            Outbox outbox({*tail.outbox_root, env.outbox_files, nullptr});
            const QueueOutcome queued =
                outbox.queue(tail.folder, tail.run_id,
                             env.connector_options.wall_now ? env.connector_options.wall_now()
                                                            : std::chrono::system_clock::now(),
                             timestamp.stamped(), timestamp.error);
            const bool in_outbox = queued.result == QueueResult::queued ||
                                   queued.result == QueueResult::queued_without_manifest;
            outcome = {in_outbox ? RunFolderState::queued : RunFolderState::complete,
                       std::string{queue_word(queued.result)}};
            if (in_outbox && !output_lost) {
                try {
                    out << "queued " << table_cell(path_to_utf8(queued.folder)) << '\n';
                    out.flush();
                } catch (...) {
                }
            }
            if (queued.result != QueueResult::queued) {
                err << outbox.queue_error(queued, tail.folder) << '\n';
                code = code == exit_code::ok ? exit_code::config : code;
            }
        }
    } catch (...) {
        // Never an exit code without its line.
        try {
            err << "error: unexpected failure\n";
        } catch (...) {
        }
        code = code == exit_code::ok ? exit_code::config : code;
    }
    return code;
}

} // namespace rp
