#pragma once

// The end of a run folder (W4.2 to W4.6), one function with one signing
// path: the pipeline calls it last for a run with --evidence, and the
// service calls it for a run folder that was left without a result
// (docs/decisions.md 2026-10-08, W4.8 point 7), with a result it built
// without a pipeline run. Beside it, what both need to get there: the holder
// of the run's signing key and the TSA's settings.

#include <rp/config.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/recording_http_client.hpp>
#include <rp/restore_command.hpp>
#include <rp/secrets.hpp>
#include <rp/signer.hpp>

#include <filesystem>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace rp {

// The run's signing key (W4.3 point 3): the text the vault's
// signing_key_base64 carried and, for a run that signs, the key parsed from
// it, in one holder that wipes both on every way out of the run, the returns
// before the run line included. The text stays in the run's Secrets until
// take() moves it here (wiped there), which the pipeline does before the
// connector is made, so the connector's copy of the secrets never holds it; a
// holder that goes before that wipes it where it is.
class RunSigningKey {
public:
    // `secrets` must outlive the holder.
    explicit RunSigningKey(Secrets& secrets) noexcept : secrets_(secrets) {}
    RunSigningKey(const RunSigningKey&) = delete;
    RunSigningKey& operator=(const RunSigningKey&) = delete;
    ~RunSigningKey();

    // The key the secrets carry, parsed (rp::SigningKey::from_base64). Throws
    // ConfigError, naming the secret and never its value, when it isn't in
    // the vault or isn't a key. Only a run that signs calls it.
    void parse();

    // Moves the text out of the Secrets, which no longer hold it.
    void take() noexcept;

    // Empty until take(), and when the vault had no key.
    const std::string& text() const noexcept { return text_; }
    // Null unless parse() made one.
    const SigningKey* key() const noexcept { return key_ ? &*key_ : nullptr; }

private:
    Secrets& secrets_;
    std::string text_;
    std::optional<SigningKey> key_;
};

// The TSA a run folder's result is timestamped by (W4.4): its URL and the PEM
// certificates a token must chain to.
struct TsaSettings {
    std::string url;
    std::string ca_pem;
};

// Config's tsa_url and tsa_ca_file, or the default TSA and the embedded root.
// Throws ConfigError (key tsa_ca_file) for a CA file that can't be read whole
// or holds no certificate: a run that could take no token says so before
// anything is done, not after the restore.
TsaSettings tsa_settings(const Config& config);

// What became of a run's folder.
enum class RunFolderState {
    none,       // the run has no folder: no --evidence, or it ended before its run line
    incomplete, // there, without a result.json
    complete,   // result.json written, so signed, and not in the outbox
    queued      // renamed to <outbox root>\outbox\<run_id>
};

// `word` says why, in fixed words:
//  - incomplete: "not_written" (a file the writer refused: a text file,
//    signature.json or result.json), "changed" (an attachment that wasn't the
//    bytes hashed when it was read back), "holds_secret", "not_signed", or
//    "invalid" (no valid result to write);
//  - complete: empty when no outbox was asked for, else why the folder isn't
//    in it: "already_queued", "already_sent", "no_outbox_folder",
//    "not_same_volume", "not_moved" or "not_complete";
//  - queued: empty, or "manifest_not_written" (the next flush makes it).
struct RunFolderOutcome {
    RunFolderState state = RunFolderState::none;
    std::string word;
};

// What the tail is given. The pointers are borrowed for the call.
struct RunFolderTail {
    // The run's folder, there and the caller's own.
    std::filesystem::path folder;
    std::string run_id;
    // The client's setting for this run (config's screenshots_enabled, or a
    // job's).
    bool screenshots_enabled = false;
    // The run's secrets, without the signing key's text, and its holder,
    // parsed and taken: the result is scanned for every secret value, the
    // key's text and its other shapes included, and signed with the key.
    const Secrets* secrets = nullptr;
    const RunSigningKey* signing = nullptr;
    // The TSA asked once the result is signed; null = none is asked.
    const TsaSettings* tsa = nullptr;
    // write_evidence_file, capture_screenshot, sign_result, make_tsa_http,
    // timestamp_nonce, outbox_files, stop_requested (the Timestamper's), and
    // connector_options' logger, sleep and wall_now.
    const RestoreCommandEnv* env = nullptr;
    // With --record the TSA's exchanges go under "tsa"; null = not recorded.
    std::shared_ptr<FixtureRecorder> recorder;
    // The outbox the finished folder is queued in; null = it stays.
    const std::filesystem::path* outbox_root = nullptr;
    // The folder's attachments, written or found: called once, first. A
    // Written without `evidence` ends the tail, each of its errors one
    // "could not be written" line.
    std::function<EvidenceBuilder::Written(EvidenceBuilder&)> attachments;
    // The result's canonical text for what the folder lists, built and
    // validated; nullopt = there is no valid result (its own line, if any, is
    // the caller's): the folder stays as it is, "invalid".
    std::function<std::optional<std::string>(const Evidence&)> result;
};

// The run folder's files, last (W4.2 point 9): the attachments, then the
// result with what it lists; the result scanned for the run's secret values,
// each attachment read back against its hash, the result signed with the
// run's key (W4.3) and a TSA asked for a token over the same bytes' hash
// (W4.4); signature.json, timestamp.tst when there is a token, result.json
// last; then, only once result.json is written, "signed <bundle_sha256> key
// <key_id>", "timestamped <time>" with a token and "evidence <folder>: ..."
// on `out` (none when `output_lost`); then, with an outbox, the folder queued
// by one rename (rp::Outbox::queue) and "queued <outbox folder>". On `err`:
// each "evidence error: ..." and "outbox error: ..." line and the "timestamp
// warning: ..." ones, as documented on run_pipeline. Nothing here changes a
// status: what fails is one line and an exit code of 0 becoming 1. Returns
// the exit code; `outcome` says what became of the folder. Never throws.
int finish_run_folder(const RunFolderTail& tail, std::ostream& out, std::ostream& err, int code,
                      bool output_lost, RunFolderOutcome& outcome) noexcept;

} // namespace rp
