#pragma once

// The run folder (W4.2, docs/decisions.md 2026-10-05): <runs root>\<run_id>\
// with result.json, veeam-session.log, items.csv and, when one was captured,
// screenshot.png. Each of those beside result.json is an attachment the result
// lists with its SHA-256 and size, so the signature over the result covers
// them. Since W4.3 (docs/decisions.md 2026-10-05, point 2) the result is
// signed as it is written: signature.json (rp/signer.hpp), which the result
// never lists, then result.json, last, and only a valid result, so a folder
// that holds it is complete, and signed. Nothing here changes a run's status.

#include <rp/checker.hpp>
#include <rp/connector.hpp>
#include <rp/expected_set.hpp>
#include <rp/run_status.hpp>
#include <rp/signer.hpp>
#include <rp/timestamper.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/logger.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

inline constexpr std::string_view kResultFileName = "result.json";
inline constexpr std::string_view kItemsCsvName = "items.csv";
inline constexpr std::string_view kSessionLogName = "veeam-session.log";
inline constexpr std::string_view kScreenshotName = "screenshot.png";

// What a log line or a CSV row that held one of the run's secret values is
// replaced by (point 6).
inline constexpr std::string_view kWithheld = "[withheld: held a secret value]";

// A screenshot larger than this is `failed` (C7.2 caps an attachment at 25 MB).
inline constexpr std::uintmax_t kMaxScreenshotBytes = 10u * 1024u * 1024u;

// Why there is no screenshot.
enum class ScreenshotReason {
    disabled,       // screenshots_enabled is off: the capturer wasn't asked
    no_page,        // no page shows the session without an interactive sign-in,
                    // or the run has no restore session to show
    no_browser,
    login_required,
    timeout,
    failed          // anything else: the capturer threw, or left no PNG
};

// "disabled", "no_page", "no_browser", "login_required", "timeout" or
// "failed"; "unknown" for a value outside the enum.
std::string_view to_string(ScreenshotReason reason) noexcept;

// Every reason's word and every attachment's name, in the schema's order: what
// a test holds the schema's enums to.
const std::vector<std::string>& screenshot_reasons();
const std::vector<std::string>& attachment_names();

// What a capturer is asked for: a PNG of the restore sessions' status page,
// written to `png` (<run folder>\screenshot.png, not there yet).
struct ScreenshotRequest {
    std::filesystem::path png;
    std::vector<std::string> session_ids;
};

// nullopt = captured, `png` written; else why not. Bounding its own time is
// the capturer's job (it answers `timeout`). What it throws is `failed`.
using ScreenshotCapturer = std::function<std::optional<ScreenshotReason>(const ScreenshotRequest&)>;

// The default capturer (point 3): `no_page`, without starting a browser.
// Veeam's only page with restore sessions, the Restore Portal, signs in
// interactively and has a certificate a browser can't be given the pin for.
std::optional<ScreenshotReason> no_screenshot_page(const ScreenshotRequest& request) noexcept;

// One file of the run folder that the result covers: never result.json, nor
// signature.json (W4.3).
struct Attachment {
    std::string name;
    std::string sha256; // of the file's bytes, 64 lower-case hex
    std::uintmax_t size_bytes = 0;
};

struct Screenshot {
    bool captured = false;
    ScreenshotReason reason = ScreenshotReason::failed; // when not captured
};

// What the result says of the run folder.
struct Evidence {
    std::vector<Attachment> attachments; // sorted by name
    Screenshot screenshot;
};

// The result's `attachments`: [{"name", "sha256", "size_bytes"}], as given.
nlohmann::json to_json(const std::vector<Attachment>& attachments);

// The result's `screenshot`: {"state": "captured"} or {"state": "unavailable",
// "reason": <to_string(reason)>}.
nlohmann::json to_json(const Screenshot& screenshot);

// What the two text files are made from; null where a step didn't run.
struct EvidenceFacts {
    const verification::ExpectedSet* expected = nullptr;
    const connector::RestoreResult* restore = nullptr;
    const verification::CheckResult* check = nullptr;
    const verification::RunVerdict* verdict = nullptr;
};

// A file's text and how many of its lines or rows were withheld.
struct EvidenceText {
    std::string text;
    std::size_t withheld = 0;
};

enum class RunFolderCheck { ok, not_a_folder_name, exists, cannot_make };

// The run folder make_run_folder made, the run's to take away again until it
// is kept: destroyed (or dropped) before keep(), the folder is removed, and
// then each level of the runs root that was made for it. Only an empty folder
// is ever removed, so nothing another run wrote goes with it. A run keeps its
// folder once its run line is out; whichever way it ends before that, nothing
// is left (W4.2 code review, points 4 and 6).
class RunFolder {
public:
    RunFolder() = default;
    RunFolder(const RunFolder&) = delete;
    RunFolder& operator=(const RunFolder&) = delete;
    ~RunFolder() { drop(); }

    // <root>\<run_id>, set whenever the run ID can name a folder (also when
    // none was made); empty before that.
    const std::filesystem::path& path() const noexcept { return path_; }

    // The folder stays, and what was made for it.
    void keep() noexcept { made_.clear(); }

    // Removes what was made and isn't kept. Never throws.
    void drop() noexcept;

private:
    friend class EvidenceBuilder;

    std::filesystem::path path_;
    // What make_run_folder made: the run folder, then the root's levels from
    // the deepest up.
    std::vector<std::filesystem::path> made_;
};

// Why a file of the run folder isn't as it should be.
enum class EvidenceFailure {
    not_written,  // the writer refused or failed
    changed,      // an attachment missing, or not the bytes that were hashed
    holds_secret, // result.json only: one of its strings holds a secret value
    not_signed    // result.json only: the signer gave no signature for it (W4.3)
};

struct EvidenceError {
    std::string file; // the file's name in the run folder
    EvidenceFailure cause = EvidenceFailure::not_written;
};

// Signs the result's canonical text, the bytes result.json is about to be
// written with: rp::Signer::sign with the run's key. nullopt = it couldn't be
// signed; what it throws is that too.
using ResultSigner = std::function<std::optional<SignedResult>(std::string_view canonical)>;

// Asks a TSA for a token over `digest`, the SHA-256 of the bytes result.json
// is about to be written with (W4.4): rp::Timestamper::stamp. What it throws
// is no token (timestamp_internal).
using ResultTimestamper =
    std::function<TimestampOutcome(std::span<const unsigned char, kSha256Bytes> digest)>;

struct EvidenceOptions {
    // The client's setting (config's screenshots_enabled; a job's, W4.8).
    bool screenshots_enabled = false;
    ScreenshotCapturer capture; // null = no_screenshot_page
    // Writes a new file, whether it did; null = rp::write_file_atomically.
    std::function<bool(const std::filesystem::path&, std::string_view)> write_file;
    // The run's secret values; an empty one is ignored. The builder wipes its
    // copy (rp::secure_wipe) when it goes.
    std::vector<std::string> secrets;
    // The result's signer (W4.3); null = nothing can be signed, and so no
    // result.json is written.
    ResultSigner sign;
    // The result's timestamper (W4.4); null = no TSA is asked and no
    // timestamp.tst is written (the builder's own tests).
    ResultTimestamper timestamp;
    // One "SECURITY: evidence: ..." line when something was withheld.
    std::shared_ptr<spdlog::logger> logger;
};

class EvidenceBuilder {
public:
    // items.csv (point 5): a header row and one row per expected item, UTF-8,
    // LF. Columns index, type, source, canary_id, name, expected_kind,
    // sha256_rule, expected_sha256, found_sha256, restore_outcome, found,
    // outcome, mismatches, verdict, code, ms. `index` and `ms` are bare
    // numbers; every other cell is in double quotes, a '"' doubled, each
    // control character a space. `name` is the expected subject or file name,
    // with a leading "'" when it starts with '=', '+', '-' or '@' (a formula to
    // a spreadsheet): the exact name is the result's. found_sha256 only for an
    // item whose expectation carries a hash (ItemCheck::found_sha256).
    // `verdict` is "verified", "failed" or "unchecked" (then `code` is its
    // error code) when the item verdicts decided the run, else "-". A cell of
    // a step that didn't run is empty. A row with a cell holding one of
    // `secrets` keeps its index, has kWithheld as its name and nothing else.
    // Pure.
    static EvidenceText items_csv(const EvidenceFacts& facts,
                                  const std::vector<std::string>& secrets = {});

    // veeam-session.log (point 6): RestoreResult::log as the connector made
    // it (one line per session and per restore event, through rp::redact),
    // each line ending in LF; a line holding one of `secrets` is kWithheld.
    // Empty without a restore result. Pure.
    static EvidenceText session_log(const connector::RestoreResult* restore,
                                    const std::vector<std::string>& secrets = {});

    // Whether `run_id` can be a folder's name (rp::is_plain_file_name): no
    // ':', no trailing '.', not "." or "..", not a DOS device's name.
    static bool can_name_folder(std::string_view run_id) noexcept;

    // Makes <root>\<run_id>, and `root` first when it isn't there. `exists`
    // when anything is at that path already (another case of the same letters
    // included): never written into, never replaced. `folder` (an empty one)
    // gets the path whenever the name is one, and with `ok` the folder itself,
    // to keep or to drop. Anything but `ok` leaves nothing this call made, the
    // root's levels included. Never throws.
    static RunFolderCheck make_run_folder(const std::filesystem::path& root,
                                          std::string_view run_id, RunFolder& folder) noexcept;

    // `folder` is one make_run_folder made, and the run kept.
    EvidenceBuilder(std::filesystem::path folder, EvidenceOptions options);
    // Wipes its copy of the run's secret values.
    ~EvidenceBuilder();
    EvidenceBuilder(const EvidenceBuilder&) = delete;
    EvidenceBuilder& operator=(const EvidenceBuilder&) = delete;

    struct Written {
        // What the result lists; nullopt when a text file couldn't be written.
        std::optional<Evidence> evidence;
        std::vector<EvidenceError> errors;
    };

    // Writes items.csv and veeam-session.log (both always, each tried even
    // when the other failed), then, when both are written, asks for the
    // screenshot: not at all when screenshots are off (`disabled`), nor for a
    // run with no restore session, which has no page to show (`no_page`); a
    // capturer that throws, or says it captured and left no file, one over
    // kMaxScreenshotBytes, one that can't be read whole (cut short, or still
    // growing) or one that doesn't start with the PNG signature, is `failed`,
    // as is a capturer that answers `disabled` or a value outside the enum;
    // what an unavailable screenshot left at the path is removed. Without
    // `with_screenshot` (a run with no valid result to list it) the capturer
    // isn't asked. Each text file's hash and size are of the bytes handed to
    // the writer, the screenshot's of the bytes read; write_result reads all
    // of them back. Never throws.
    Written write_attachments(const EvidenceFacts& facts, bool with_screenshot = true) noexcept;

    // Refuses a result one of whose strings holds one of the run's secret
    // values (`holds_secret`, with one "SECURITY: evidence: ..." log line):
    // the result names every sampled item, so a subject or a file name a row
    // of items.csv was withheld for is in it too. The strings as JSON reads
    // them, not the text, where an escape would hide one. Then reads each
    // attachment back and compares it with its hash and size (`changed`,
    // naming the first that differs or is gone). Then, W4.3, asks the signer
    // for the signature of exactly `canonical` (`not_signed`, the file
    // result.json, when there is no signer, or it answers nothing or
    // throws). Then, W4.4, asks the timestamper for a token over the SHA-256
    // of `canonical`; no token is never a failure here. Then writes
    // signature.json (`not_written`, naming it), timestamp.tst when there is
    // a token (one that can't be written, or is over kMaxTimestampFileBytes,
    // is no token: timestamp_not_written) and, last, result.json, exactly
    // `canonical` (`not_written`); when that one can't be written,
    // signature.json and timestamp.tst are removed again, so neither stays
    // beside no result. So result.json there means: signed, and the
    // timestamp attempt over, with a token beside it or without one.
    // nullopt = written; `signature`, when given, is then what the signer
    // made, and `timestamp` the token as it was written, or why there is
    // none (attempts 0 when no timestamper was asked); both are untouched
    // otherwise. Never throws.
    std::optional<EvidenceError> write_result(const Evidence& evidence,
                                              std::string_view canonical,
                                              SignedResult* signature = nullptr,
                                              TimestampOutcome* timestamp = nullptr) noexcept;

    const std::filesystem::path& folder() const noexcept { return folder_; }

private:
    bool write(std::string_view name, std::string_view content) noexcept;
    Screenshot capture(const connector::RestoreResult* restore,
                       std::vector<Attachment>& attachments) noexcept;

    std::filesystem::path folder_;
    EvidenceOptions options_;
};

} // namespace rp
