#pragma once

// The local outbox (W4.6, docs/decisions.md 2026-10-07): a complete, signed
// run folder is queued under <root>\outbox\<run_id>, uploaded later, oldest
// first, with retries, and moved to <root>\sent\<run_id>. Nothing signed is
// ever lost or changed: a folder is queued and sent by one rename, never a
// copy; the one file written in a queued folder is manifest.json, the
// Worker's own record, which is never uploaded; every byte that is uploaded
// is read and checked against what the run signed first; and only runs the
// Cloud already has are ever deleted. docs/verification.md, "The outbox".

#include <rp/rfc3161.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

inline constexpr std::string_view kOutboxFolderName = "outbox";
inline constexpr std::string_view kSentFolderName = "sent";
inline constexpr std::string_view kOutboxManifestName = "manifest.json";
inline constexpr std::string_view kOutboxManifestFormat = "restoreproof.outbox-manifest.v1";

// A manifest.json larger than this isn't one.
inline constexpr std::uintmax_t kMaxManifestBytes = 64u * 1024u;
// The most attempts a manifest counts.
inline constexpr int kMaxUploadAttempts = 1'000'000;

// Point 4's caps: outbox\ and sent\ together, and how long a sent run is kept.
inline constexpr std::uintmax_t kOutboxCapBytes = 500ull * 1024u * 1024u;
inline constexpr std::chrono::seconds kSentKept{30 * 24 * 3600};

// The wait after a failed attempt: 60 s, doubled per attempt, at most an hour.
inline constexpr std::chrono::seconds kFirstUploadRetry{60};
inline constexpr std::chrono::seconds kMaxUploadRetry{3600};

// One flush at a time (point 3): the named mutex `outbox flush` takes.
inline constexpr std::wstring_view kOutboxMutex = L"Global\\RestoreProof-outbox";

// A manifest's last_error.
namespace upload_code {
inline constexpr std::string_view kUnreachable = "upload_unreachable"; // no answer: no
                                                                       // connection, a TLS
                                                                       // failure, a drop
inline constexpr std::string_view kTimeout = "upload_timeout";
inline constexpr std::string_view kInternal = "upload_internal"; // the uploader itself failed
// Then the answer's status, three digits: any answer but 202.
inline constexpr std::string_view kHttpPrefix = "upload_http_";
// Not an attempt: a file of the folder isn't what the run signed.
inline constexpr std::string_view kFolderChanged = "folder_changed";
} // namespace upload_code

// Not a code and never in a manifest: a flush's stdout word, "kept <run>:
// not_read", for a run one of whose files is there but couldn't be read at
// that moment (held open by another process). Nothing is written; the next
// flush tries again.
inline constexpr std::string_view kFlushNotRead = "not_read";

// Whether `code` is what an uploader may answer for a failed attempt:
// upload_unreachable, upload_timeout, upload_internal, or upload_http_ and a
// status of three digits.
bool is_upload_error(std::string_view code) noexcept;

// now + min(60 s x 2^(attempts - 1), 3600 s) is when a run that has failed
// `attempts` times is tried again: 60, 120, 240, 480, 960, 1920, then 3600 s.
// An `attempts` below 1 counts as 1.
std::chrono::seconds upload_retry_delay(int attempts) noexcept;

// A manifest's time: UTC, whole seconds, YYYY-MM-DDTHH:MM:SSZ. Two such texts
// compare by byte as their times do.
std::string outbox_time_text(std::chrono::system_clock::time_point time);

// manifest.json (point 2).
struct OutboxManifest {
    std::string run_id;
    std::string queued_at;
    int attempts = 0;
    std::optional<std::string> next_attempt_at;
    std::optional<std::string> last_attempt_at;
    std::optional<std::string> last_error;
    // timestamp.state and timestamp.code: whether the run got a token, and
    // the W4.4 code when it didn't (tsa_error).
    bool timestamped = false;
    std::optional<std::string> timestamp_code;
    // The folder's names when it was queued, sorted by byte, without
    // manifest.json.
    std::vector<std::string> files;
    // Only once the Cloud has answered 202.
    std::optional<std::string> sent_at;
};

// The manifest's canonical-json-v1 text: exactly what the file holds.
std::string manifest_text(const OutboxManifest& manifest);

// The manifest `text` holds for the run `run_id`, or nullopt for anything
// that isn't one: not its own canonical form, another key set or kind, another
// format or run ID, attempts outside 0 to kMaxUploadAttempts, a time of
// another shape, a last_error that is no code, a timestamp code that isn't 1
// to 64 printable ASCII characters. Never throws but for no memory.
std::optional<OutboxManifest> parse_manifest(std::string_view text, std::string_view run_id);

// One part of the upload's multipart body.
struct UploadPart {
    std::string name;         // "result", "signature", "timestamp", or an attachment's name
    std::string filename;     // the file's name in the run folder
    std::string content_type; // "application/json" or "application/octet-stream"
    std::string bytes;        // the file, whole
};

struct UploadAnswer {
    bool accepted = false; // the Cloud answered 202
    std::string error;     // an upload_code, when not accepted
};

// What sends one run. The real one is rp::CloudUploader (rp/uploader.hpp);
// what it throws is upload_internal, and so is an error that is no code.
class IUploader {
public:
    virtual ~IUploader() = default;
    virtual UploadAnswer upload(const std::string& run_id,
                                const std::vector<UploadPart>& parts) = 0;
};

// The outbox's calls into the file system, each null = the real one
// (src/folder_ops.hpp, src/atomic_file.hpp).
struct OutboxFiles {
    // One rename, never a copy: 0, or Windows' error code.
    std::function<unsigned long(const std::filesystem::path& from,
                                const std::filesystem::path& to)>
        move_folder;
    // Writes manifest.json whole, over the one that is there or not; whether
    // it did.
    std::function<bool(const std::filesystem::path&, std::string_view)> write_manifest;
    // Removes a sent run's folder; whether it is gone.
    std::function<bool(const std::filesystem::path&)> remove_folder;
    // A run folder's size in bytes; nullopt when it can't be read.
    std::function<std::optional<std::uintmax_t>(const std::filesystem::path&)> folder_bytes;
    // Whether two paths, which needn't exist yet, are on one volume, so a
    // rename between them is one and never a copy; nullopt when it can't be
    // told.
    std::function<std::optional<bool>(const std::filesystem::path&, const std::filesystem::path&)>
        same_volume;
};

struct OutboxOptions {
    // <root>\outbox and <root>\sent.
    std::filesystem::path root;
    OutboxFiles files;
    // Reads a token's imprint; null = rp::openssl_rfc3161().
    const Rfc3161* rfc3161 = nullptr;
};

enum class QueueResult {
    queued,
    // Moved, but manifest.json couldn't be written: the next flush makes it.
    queued_without_manifest,
    not_complete,     // no result.json in the run folder: never queued
    already_queued,   // <root>\outbox\<run_id> is there
    already_sent,     // <root>\sent\<run_id> is there
    no_outbox_folder, // <root>\outbox couldn't be made
    not_same_volume,  // the rename would be a copy
    not_moved         // the rename failed; `error` is Windows' code
};

struct QueueOutcome {
    QueueResult result = QueueResult::not_complete;
    // <root>\outbox\<run_id>.
    std::filesystem::path folder;
    unsigned long error = 0;
};

// One folder under outbox\ that holds a result.json.
struct QueuedRun {
    std::string run_id;
    // nullopt: no readable manifest.json (the next flush makes one).
    std::optional<OutboxManifest> manifest;
};

struct OutboxListing {
    // False: the root, or outbox\ or sent\ under it, is there and can't be
    // listed. One that isn't there is empty.
    bool readable = true;
    std::vector<QueuedRun> queued; // by run ID
    std::size_t sent = 0;          // folders under sent
    // "outbox error: <folder>: no result.json; not a queued run", per folder
    // under outbox\ that isn't a run.
    std::vector<std::string> errors;
};

// What one flush did. The lines are whole, without their line end.
struct FlushReport {
    bool readable = true;         // as OutboxListing's
    std::vector<std::string> out; // pruned, sent, kept, waiting, moved
    std::vector<std::string> err; // "outbox error: ..." and "outbox warning: ..."
    bool errors = false;          // an "outbox error" line is among them
    std::size_t queued = 0;       // runs still under outbox
    std::size_t sent = 0;         // folders under sent
};

class Outbox {
public:
    explicit Outbox(OutboxOptions options);

    std::filesystem::path outbox_folder() const;
    std::filesystem::path sent_folder() const;

    // Queues the finished run folder `run_folder` (one that holds result.json)
    // as <root>\outbox\<run_id>: makes <root>\outbox when it isn't there,
    // renames the folder, then writes its manifest there (attempts 0,
    // queued_at `now`, timestamp.state and code as given, a null code for an
    // empty one). Anything but queued and queued_without_manifest leaves the
    // run folder where and as it was. Never throws but for no memory.
    QueueOutcome queue(const std::filesystem::path& run_folder, std::string_view run_id,
                       std::chrono::system_clock::time_point now, bool timestamped,
                       std::string_view timestamp_code);

    // The "outbox error: ..." line for an outcome that isn't `queued`, without
    // its line end; empty for `queued`.
    std::string queue_error(const QueueOutcome& outcome,
                            const std::filesystem::path& run_folder) const;

    // Before a run with --outbox (the W4.6 review, finding 1): what would stop
    // the finished folder <runs_root>\<run_id> from being queued, found before
    // the secrets and any Veeam call rather than after the restore. With
    // `run_id` (a --run-id; a run without one makes its ID later), first a run
    // of that ID already queued or sent; then <root>\outbox is made when it
    // isn't there; then the runs root and <root>\outbox are held to one volume
    // (one that can't be told is let through: the rename says). The "outbox
    // error: ...; nothing was done" line, without its line end, or empty when
    // nothing stands in the way. Never throws but for no memory.
    std::string prepare(const std::filesystem::path& runs_root,
                        std::optional<std::string_view> run_id) const;

    // What is queued and how many runs are sent; reads only.
    OutboxListing list() const;

    // One pass, no waiting (points 3 and 4): prunes sent\, then tries every
    // queued run that is due, oldest queued_at first. Never throws but for no
    // memory.
    FlushReport flush(IUploader& uploader, std::chrono::system_clock::time_point now);

private:
    OutboxOptions options_;
};

} // namespace rp
