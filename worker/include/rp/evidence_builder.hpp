#pragma once

// The run folder (W4.2, docs/decisions.md 2026-10-05): <runs root>\<run_id>\
// with result.json, veeam-session.log, items.csv and, when one was captured,
// screenshot.png. Each file beside result.json is an attachment the result
// lists with its SHA-256 and size, so W4.3's signature over the result covers
// them; result.json is written last, and only a valid result, so a folder
// that holds it is complete. Nothing here changes a run's status.

#include <rp/checker.hpp>
#include <rp/connector.hpp>
#include <rp/expected_set.hpp>
#include <rp/run_status.hpp>

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
    no_page,        // no page shows the session without an interactive sign-in
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

// One file beside result.json.
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

// Why a file of the run folder isn't as it should be.
enum class EvidenceFailure {
    not_written, // the writer refused or failed
    changed      // an attachment missing, or not the bytes that were hashed
};

struct EvidenceError {
    std::string file; // the file's name in the run folder
    EvidenceFailure cause = EvidenceFailure::not_written;
};

struct EvidenceOptions {
    // The client's setting (config's screenshots_enabled; a job's, W4.8).
    bool screenshots_enabled = false;
    ScreenshotCapturer capture; // null = no_screenshot_page
    // Writes a new file, whether it did; null = rp::write_file_atomically.
    std::function<bool(const std::filesystem::path&, std::string_view)> write_file;
    // The run's secret values; an empty one is ignored.
    std::vector<std::string> secrets;
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
    // included): never written into, never replaced. `folder` is set to the
    // path whenever the name is one. Never throws.
    static RunFolderCheck make_run_folder(const std::filesystem::path& root,
                                          std::string_view run_id,
                                          std::filesystem::path& folder) noexcept;

    // `folder` is one make_run_folder made.
    EvidenceBuilder(std::filesystem::path folder, EvidenceOptions options);

    struct Written {
        // What the result lists; nullopt when a text file couldn't be written.
        std::optional<Evidence> evidence;
        std::vector<EvidenceError> errors;
    };

    // Writes items.csv and veeam-session.log (both always, each tried even
    // when the other failed), then, when both are written, asks for the
    // screenshot: not at all when screenshots are off (`disabled`); a capturer that throws, or says it
    // captured and left no file, one over kMaxScreenshotBytes or one that
    // doesn't start with the PNG signature, is `failed`, as is a capturer
    // that answers `disabled` or a value outside the enum; what an
    // unavailable screenshot left at the path is removed. Without
    // `with_screenshot` (a run with no valid result to list it) the capturer
    // isn't asked. Each text file's hash and size are of the bytes handed to
    // the writer, the screenshot's of the bytes read; write_result reads all
    // of them back. Never throws.
    Written write_attachments(const EvidenceFacts& facts, bool with_screenshot = true) noexcept;

    // Reads each attachment back and compares it with its hash and size
    // (`changed`, naming the first that differs or is gone), then writes
    // result.json, exactly `canonical` (`not_written`). nullopt = written.
    // Never throws.
    std::optional<EvidenceError> write_result(const Evidence& evidence,
                                              std::string_view canonical) noexcept;

    const std::filesystem::path& folder() const noexcept { return folder_; }

private:
    bool write(std::string_view name, std::string_view content) noexcept;
    Screenshot capture(const connector::RestoreResult* restore,
                       std::vector<Attachment>& attachments) noexcept;

    std::filesystem::path folder_;
    EvidenceOptions options_;
};

} // namespace rp
