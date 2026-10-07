#include <rp/outbox.hpp>

#include <rp/canonical_json.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/sha256.hpp>
#include <rp/signer.hpp>

#include "atomic_file.hpp"
#include "file_read.hpp"
#include "folder_ops.hpp"
#include "path_utf8.hpp"
#include "text_table.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <format>
#include <tuple>
#include <utility>

namespace rp {

namespace {

using nlohmann::json;
using std::filesystem::path;

constexpr std::string_view kStateTimestamped = "timestamped";
constexpr std::string_view kStateNotTimestamped = "not_timestamped";
constexpr std::string_view kJsonType = "application/json";
constexpr std::string_view kBytesType = "application/octet-stream";
constexpr std::size_t kMaxTimestampCode = 64;

std::string shown(const path& p)
{
    return table_cell(path_to_utf8(p));
}

// YYYY-MM-DDTHH:MM:SSZ.
bool is_time(std::string_view text) noexcept
{
    constexpr std::string_view shape = "dddd-dd-ddTdd:dd:ddZ";
    if (text.size() != shape.size()) {
        return false;
    }
    for (std::size_t i = 0; i < shape.size(); ++i) {
        const bool digit = text[i] >= '0' && text[i] <= '9';
        if (shape[i] == 'd' ? !digit : text[i] != shape[i]) {
            return false;
        }
    }
    return true;
}

bool is_last_error(std::string_view code) noexcept
{
    return code == upload_code::kFolderChanged || is_upload_error(code);
}

bool is_timestamp_code(std::string_view code) noexcept
{
    return !code.empty() && code.size() <= kMaxTimestampCode &&
           std::ranges::all_of(code, [](char c) { return c >= ' ' && c <= '~'; });
}

// The key's string, held to `rule`, or nothing for a null; false for a key
// that isn't there, another kind, or a string the rule refuses.
template <typename Rule>
bool read_nullable(const json& object, std::string_view key, Rule rule,
                   std::optional<std::string>& into)
{
    const auto it = object.find(key);
    if (it == object.end() || !(it->is_null() || it->is_string())) {
        return false;
    }
    if (it->is_string()) {
        into = it->get<std::string>();
    }
    return !into || rule(*into);
}

// Whether `text` is `document`'s canonical form. One return after the handler.
bool is_canonical(const json& document, std::string_view text)
{
    bool same = false;
    try {
        same = canonical_json(document) == text;
    } catch (const CanonicalJsonError&) {
        same = false;
    }
    return same;
}

json nullable(const std::optional<std::string>& text)
{
    return text ? json(*text) : json(nullptr);
}

// The names of the folders in `folder`, sorted by byte; empty when `folder`
// isn't there, nullopt when something is there that can't be listed.
std::optional<std::vector<std::string>> folders_in(const path& folder)
{
    if (path_kind(folder) == PathKind::none) {
        return std::vector<std::string>{};
    }
    std::optional<std::vector<std::string>> names = list_folder(folder);
    if (!names) {
        return std::nullopt;
    }
    std::erase_if(*names, [&](const std::string& name) {
        const std::optional<path> part = path_from_utf8(name);
        return !part || path_kind(folder / *part) != PathKind::folder;
    });
    return names;
}

// The manifest in `folder`, the run `run_id`'s, or nullopt.
std::optional<OutboxManifest> read_manifest(const path& folder, std::string_view run_id)
{
    const FileRead read = read_whole_file(folder / kOutboxManifestName, kMaxManifestBytes);
    return read.state == FileState::read ? parse_manifest(read.bytes, run_id) : std::nullopt;
}

// Whether `folder`, named `run_id`, holds a run: a plain name and a
// result.json.
bool is_run_folder(const path& folder, std::string_view run_id)
{
    const std::optional<path> name = path_from_utf8(run_id);
    return name && is_plain_file_name(name->native()) &&
           path_kind(folder / kResultFileName) == PathKind::file;
}

std::string not_a_run(const path& folder)
{
    return "outbox error: " + shown(folder) + ": no result.json; not a queued run";
}

// The run's files as the upload's parts, each read whole and checked against
// what the run signed (point 3); or nullopt, with `changed` the file that
// isn't as it was.
std::optional<std::vector<UploadPart>> checked_parts(const path& folder,
                                                     const OutboxManifest& manifest,
                                                     const Rfc3161& rfc3161, std::string& changed)
{
    std::vector<UploadPart> parts;
    const auto refuse = [&](std::string_view file) {
        changed = table_cell(file);
        return std::nullopt;
    };

    FileRead result = read_whole_file(folder / kResultFileName, kMaxResultFileBytes);
    const json document = result.state == FileState::read ? json::parse(result.bytes, nullptr, false)
                                                          : json(nullptr);
    const auto id = document.is_object() ? document.find("run_id") : document.end();
    if (id == document.end() || !id->is_string() || id->get<std::string>() != manifest.run_id) {
        return refuse(kResultFileName);
    }
    const std::array<unsigned char, 32> digest = sha256_bytes(result.bytes);
    const std::string hash = sha256_hex(result.bytes);

    FileRead signature = read_whole_file(folder / kSignatureFileName, kMaxSignatureFileBytes);
    const json signed_as = signature.state == FileState::read
                               ? json::parse(signature.bytes, nullptr, false)
                               : json(nullptr);
    const auto bundle = signed_as.is_object() ? signed_as.find("bundle_sha256") : signed_as.end();
    if (bundle == signed_as.end() || !bundle->is_string()) {
        return refuse(kSignatureFileName);
    }
    // The signature names another hash: the result isn't the one it signed.
    if (bundle->get<std::string>() != hash) {
        return refuse(kResultFileName);
    }
    parts.push_back({"result", std::string{kResultFileName}, std::string{kJsonType},
                     std::move(result.bytes)});
    parts.push_back({"signature", std::string{kSignatureFileName}, std::string{kJsonType},
                     std::move(signature.bytes)});

    // The token: there exactly when the manifest says so, and over that hash.
    const path token_path = folder / kTimestampFileName;
    if (manifest.timestamped) {
        FileRead token = read_whole_file(token_path, kMaxTimestampFileBytes);
        const std::optional<TimestampTokenInfo> info =
            token.state == FileState::read ? rfc3161.parse_token(token.bytes) : std::nullopt;
        if (!info || !info->sha256 || !std::ranges::equal(info->imprint, digest)) {
            return refuse(kTimestampFileName);
        }
        parts.push_back({"timestamp", std::string{kTimestampFileName}, std::string{kBytesType},
                         std::move(token.bytes)});
    } else if (path_kind(token_path) != PathKind::none) {
        return refuse(kTimestampFileName);
    }

    const auto listed = document.find("attachments");
    if (listed == document.end() || !(listed->is_null() || listed->is_array())) {
        return refuse(kResultFileName);
    }
    // A null has no elements.
    for (const json& entry : listed->is_array() ? *listed : json::array()) {
        const auto name = entry.is_object() ? entry.find("name") : entry.end();
        const auto sha256 = entry.is_object() ? entry.find("sha256") : entry.end();
        const auto size = entry.is_object() ? entry.find("size_bytes") : entry.end();
        if (name == entry.end() || !name->is_string() || sha256 == entry.end() ||
            !sha256->is_string() || size == entry.end() || !size->is_number_unsigned()) {
            return refuse(kResultFileName);
        }
        const std::string file = name->get<std::string>();
        const std::optional<path> part = path_from_utf8(file);
        if (!part || !is_plain_file_name(part->native()) || file == kResultFileName ||
            file == kSignatureFileName || file == kTimestampFileName ||
            file == kOutboxManifestName) {
            return refuse(kResultFileName);
        }
        FileRead bytes = read_whole_file(folder / *part, size->get<std::uintmax_t>());
        if (bytes.state != FileState::read || bytes.bytes.size() != size->get<std::uintmax_t>() ||
            sha256_hex(bytes.bytes) != sha256->get<std::string>()) {
            return refuse(file);
        }
        parts.push_back({file, file, std::string{kBytesType}, std::move(bytes.bytes)});
    }
    return parts;
}

// A sent run with its sent_at, for the caps.
struct SentRun {
    std::string sent_at;
    std::string run_id;
    std::uintmax_t bytes = 0;
};

} // namespace

bool is_upload_error(std::string_view code) noexcept
{
    if (code == upload_code::kUnreachable || code == upload_code::kTimeout ||
        code == upload_code::kInternal) {
        return true;
    }
    const std::string_view prefix = upload_code::kHttpPrefix;
    return code.size() == prefix.size() + 3 && code.starts_with(prefix) &&
           std::ranges::all_of(code.substr(prefix.size()),
                               [](char c) { return c >= '0' && c <= '9'; });
}

std::chrono::seconds upload_retry_delay(int attempts) noexcept
{
    std::chrono::seconds delay = kFirstUploadRetry;
    for (int n = 1; n < attempts && delay < kMaxUploadRetry; ++n) {
        delay *= 2;
    }
    return std::min(delay, kMaxUploadRetry);
}

std::string outbox_time_text(std::chrono::system_clock::time_point time)
{
    return timestamp_time_text(
        std::chrono::floor<std::chrono::seconds>(time).time_since_epoch().count());
}

std::string manifest_text(const OutboxManifest& manifest)
{
    json document{
        {"attempts", manifest.attempts},
        {"files", manifest.files},
        {"format", kOutboxManifestFormat},
        {"last_attempt_at", nullable(manifest.last_attempt_at)},
        {"last_error", nullable(manifest.last_error)},
        {"next_attempt_at", nullable(manifest.next_attempt_at)},
        {"queued_at", manifest.queued_at},
        {"run_id", manifest.run_id},
        {"timestamp",
         {{"code", nullable(manifest.timestamp_code)},
          {"state", manifest.timestamped ? kStateTimestamped : kStateNotTimestamped}}},
    };
    if (manifest.sent_at) {
        document["sent_at"] = *manifest.sent_at;
    }
    return canonical_json(document);
}

std::optional<OutboxManifest> parse_manifest(std::string_view text, std::string_view run_id)
{
    const json document = json::parse(text, nullptr, false);
    if (!document.is_object() || !is_canonical(document, text)) {
        return std::nullopt;
    }
    const bool sent = document.contains("sent_at");
    OutboxManifest manifest;
    std::optional<std::string> format;
    std::optional<std::string> id;
    std::optional<std::string> queued_at;
    const auto any = [](const std::string&) { return true; };
    if (document.size() != (sent ? 10u : 9u) || !read_nullable(document, "format", any, format) ||
        format != kOutboxManifestFormat || !read_nullable(document, "run_id", any, id) ||
        id != run_id || !read_nullable(document, "queued_at", is_time, queued_at) || !queued_at ||
        !read_nullable(document, "next_attempt_at", is_time, manifest.next_attempt_at) ||
        !read_nullable(document, "last_attempt_at", is_time, manifest.last_attempt_at) ||
        !read_nullable(document, "last_error", is_last_error, manifest.last_error) ||
        (sent && (!read_nullable(document, "sent_at", is_time, manifest.sent_at) ||
                  !manifest.sent_at))) {
        return std::nullopt;
    }
    manifest.run_id = std::move(*id);
    manifest.queued_at = std::move(*queued_at);

    const auto attempts = document.find("attempts");
    if (attempts == document.end() || !attempts->is_number_unsigned() ||
        attempts->get<std::uint64_t>() > static_cast<std::uint64_t>(kMaxUploadAttempts)) {
        return std::nullopt;
    }
    manifest.attempts = attempts->get<int>();

    const auto timestamp = document.find("timestamp");
    std::optional<std::string> state;
    if (timestamp == document.end() || !timestamp->is_object() || timestamp->size() != 2 ||
        !read_nullable(*timestamp, "state", any, state) ||
        (state != kStateTimestamped && state != kStateNotTimestamped) ||
        !read_nullable(*timestamp, "code", is_timestamp_code, manifest.timestamp_code)) {
        return std::nullopt;
    }
    manifest.timestamped = state == kStateTimestamped;

    const auto files = document.find("files");
    if (files == document.end() || !files->is_array() ||
        !std::ranges::all_of(*files, [](const json& name) { return name.is_string(); })) {
        return std::nullopt;
    }
    manifest.files = files->get<std::vector<std::string>>();
    return manifest;
}

Outbox::Outbox(OutboxOptions options) : options_(std::move(options))
{
    OutboxFiles& files = options_.files;
    if (!files.move_folder) {
        files.move_folder = move_folder;
    }
    if (!files.write_manifest) {
        files.write_manifest = [](const path& file, std::string_view text) {
            AtomicWriteOptions replacing;
            replacing.replace = true;
            return write_file_atomically(file, text, replacing);
        };
    }
    if (!files.remove_folder) {
        files.remove_folder = remove_folder;
    }
    if (!files.folder_bytes) {
        files.folder_bytes = folder_bytes;
    }
    if (options_.rfc3161 == nullptr) {
        options_.rfc3161 = &openssl_rfc3161();
    }
}

std::filesystem::path Outbox::outbox_folder() const
{
    return options_.root / kOutboxFolderName;
}

std::filesystem::path Outbox::sent_folder() const
{
    return options_.root / kSentFolderName;
}

QueueOutcome Outbox::queue(const std::filesystem::path& run_folder, std::string_view run_id,
                           std::chrono::system_clock::time_point now, bool timestamped,
                           std::string_view timestamp_code)
{
    QueueOutcome outcome;
    const std::optional<path> name = path_from_utf8(run_id);
    std::optional<std::vector<std::string>> names = list_folder(run_folder);
    if (!name || !names || !is_run_folder(run_folder, run_id)) {
        return outcome;
    }
    outcome.folder = outbox_folder() / *name;
    if (path_kind(outcome.folder) != PathKind::none) {
        outcome.result = QueueResult::already_queued;
        return outcome;
    }
    if (path_kind(sent_folder() / *name) != PathKind::none) {
        outcome.result = QueueResult::already_sent;
        return outcome;
    }
    if (!make_folder(outbox_folder())) {
        outcome.result = QueueResult::no_outbox_folder;
        return outcome;
    }
    outcome.error = options_.files.move_folder(run_folder, outcome.folder);
    if (outcome.error != 0) {
        outcome.result = outcome.error == kNotSameVolume ? QueueResult::not_same_volume
                                                         : QueueResult::not_moved;
        return outcome;
    }

    OutboxManifest manifest;
    manifest.run_id = std::string{run_id};
    manifest.queued_at = outbox_time_text(now);
    manifest.timestamped = timestamped;
    if (!timestamped && is_timestamp_code(timestamp_code)) {
        manifest.timestamp_code = std::string{timestamp_code};
    }
    // A name that isn't UTF-8 (NTFS takes one) has no place in a JSON string.
    std::erase_if(*names, [](const std::string& file) {
        return file == kOutboxManifestName || !path_from_utf8(file);
    });
    manifest.files = std::move(*names);
    const bool written = options_.files.write_manifest(outcome.folder / kOutboxManifestName,
                                                       manifest_text(manifest));
    outcome.result = written ? QueueResult::queued : QueueResult::queued_without_manifest;
    return outcome;
}

std::string Outbox::queue_error(const QueueOutcome& outcome,
                                const std::filesystem::path& run_folder) const
{
    const std::string from = "outbox error: " + shown(run_folder) + ": ";
    const std::string moved = "couldn't be moved to " + shown(outcome.folder);
    switch (outcome.result) {
    case QueueResult::queued:
        break;
    case QueueResult::queued_without_manifest:
        return "outbox error: " + shown(outcome.folder / kOutboxManifestName) +
               ": could not be written; the next flush makes it";
    case QueueResult::not_complete:
        return from + "no result.json; not queued";
    case QueueResult::already_queued:
        return "outbox error: " + shown(outcome.folder) + ": already queued";
    case QueueResult::already_sent:
        return "outbox error: " + shown(sent_folder() / outcome.folder.filename()) +
               ": already sent";
    case QueueResult::no_outbox_folder:
        return "outbox error: " + shown(outbox_folder()) + ": the folder couldn't be made";
    case QueueResult::not_same_volume:
        return from + moved + ": not on the same volume";
    case QueueResult::not_moved:
        return from + moved + std::format(" (error {})", outcome.error);
    }
    return {};
}

OutboxListing Outbox::list() const
{
    OutboxListing listing;
    const std::optional<std::vector<std::string>> queued = folders_in(outbox_folder());
    const std::optional<std::vector<std::string>> sent = folders_in(sent_folder());
    if (!queued || !sent) {
        listing.readable = false;
        return listing;
    }
    listing.sent = sent->size();
    for (const std::string& run_id : *queued) {
        const path folder = outbox_folder() / *path_from_utf8(run_id);
        if (!is_run_folder(folder, run_id)) {
            listing.errors.push_back(not_a_run(folder));
            continue;
        }
        listing.queued.push_back({run_id, read_manifest(folder, run_id)});
    }
    return listing;
}

FlushReport Outbox::flush(IUploader& uploader, std::chrono::system_clock::time_point now)
{
    FlushReport report;
    const std::string now_text = outbox_time_text(now);
    const OutboxFiles& files = options_.files;
    const auto error = [&](const std::string& what) {
        report.err.push_back("outbox error: " + what);
        report.errors = true;
    };
    const auto warning = [&](const std::string& what) {
        report.err.push_back("outbox warning: " + what);
    };

    const std::optional<std::vector<std::string>> queued_names = folders_in(outbox_folder());
    const std::optional<std::vector<std::string>> sent_names = folders_in(sent_folder());
    if (!queued_names || !sent_names) {
        report.readable = false;
        error(shown(options_.root) + ": the outbox can't be read");
        return report;
    }

    // The queue: every folder that is a run, with its manifest, made again
    // where there is none that reads.
    std::vector<OutboxManifest> queue;
    std::uintmax_t queue_bytes = 0;
    for (const std::string& run_id : *queued_names) {
        const path folder = outbox_folder() / *path_from_utf8(run_id);
        if (!is_run_folder(folder, run_id)) {
            error(shown(folder) + ": no result.json; not a queued run");
            continue;
        }
        queue_bytes += files.folder_bytes(folder).value_or(0);
        std::optional<OutboxManifest> manifest = read_manifest(folder, run_id);
        if (!manifest) {
            manifest.emplace();
            manifest->run_id = run_id;
            manifest->queued_at = now_text;
            manifest->timestamped = path_kind(folder / kTimestampFileName) == PathKind::file;
            std::vector<std::string> names = list_folder(folder).value_or(std::vector<std::string>{});
            std::erase_if(names, [](const std::string& file) {
                return file == kOutboxManifestName || !path_from_utf8(file);
            });
            manifest->files = std::move(names);
            // Not written: the run is tried all the same, and what the attempt
            // writes is this manifest.
            static_cast<void>(
                files.write_manifest(folder / kOutboxManifestName, manifest_text(*manifest)));
            warning(shown(folder) + ": manifest.json was made again");
        }
        queue.push_back(std::move(*manifest));
    }

    // The caps (point 4): only runs the Cloud has, by their sent_at.
    std::vector<SentRun> dated;
    std::uintmax_t sent_bytes = 0;
    report.sent = sent_names->size();
    for (const std::string& run_id : *sent_names) {
        const path folder = sent_folder() / *path_from_utf8(run_id);
        const std::uintmax_t bytes = files.folder_bytes(folder).value_or(0);
        sent_bytes += bytes;
        const std::optional<OutboxManifest> manifest = read_manifest(folder, run_id);
        if (manifest && manifest->sent_at) {
            dated.push_back({*manifest->sent_at, run_id, bytes});
        } else {
            warning(shown(folder) + ": no readable manifest.json; not pruned");
        }
    }
    std::ranges::sort(dated, {}, [](const SentRun& run) {
        return std::tie(run.sent_at, run.run_id);
    });
    const std::string kept_from = outbox_time_text(now - kSentKept);
    for (const SentRun& run : dated) {
        const bool old = run.sent_at < kept_from;
        if (!old && queue_bytes + sent_bytes <= kOutboxCapBytes) {
            break;
        }
        const path folder = sent_folder() / *path_from_utf8(run.run_id);
        if (!files.remove_folder(folder)) {
            warning(shown(folder) + ": couldn't be removed");
            continue;
        }
        sent_bytes -= run.bytes;
        --report.sent;
        report.out.push_back("pruned " + table_cell(run.run_id));
    }
    if (queue_bytes > kOutboxCapBytes) {
        warning(std::format("the outbox holds {} MB, over the {} MB cap",
                            queue_bytes / (1024u * 1024u), kOutboxCapBytes / (1024u * 1024u)));
    }

    // The uploads: oldest first.
    std::ranges::sort(queue, {}, [](const OutboxManifest& run) {
        return std::tie(run.queued_at, run.run_id);
    });
    for (OutboxManifest& manifest : queue) {
        const std::string id = table_cell(manifest.run_id);
        const path name = *path_from_utf8(manifest.run_id);
        const path folder = outbox_folder() / name;
        const path manifest_file = folder / kOutboxManifestName;
        const path sent = sent_folder() / name;
        // To sent\: the last step of this flush's upload, or all that is left
        // of an earlier one's.
        const auto move_to_sent = [&](std::string_view word) {
            // A sent\ that can't be made is the move's failure.
            static_cast<void>(make_folder(sent_folder()));
            const unsigned long moved = files.move_folder(folder, sent);
            if (moved != 0) {
                error(shown(folder) +
                      std::format(": uploaded, but couldn't be moved to sent (error {})", moved));
                ++report.queued;
                return;
            }
            ++report.sent;
            report.out.push_back(std::string{word} + " " + id);
        };
        if (manifest.sent_at) {
            move_to_sent("moved");
            continue;
        }
        ++report.queued;
        if (manifest.next_attempt_at && *manifest.next_attempt_at > now_text) {
            report.out.push_back("waiting " + id + ": next at " + *manifest.next_attempt_at);
            continue;
        }
        if (path_kind(sent) != PathKind::none) {
            error(shown(sent) + ": already sent");
            continue;
        }
        std::string changed;
        const std::optional<std::vector<UploadPart>> parts =
            checked_parts(folder, manifest, *options_.rfc3161, changed);
        if (!parts) {
            error(shown(folder) + ": " + changed + " changed since it was signed");
            manifest.last_error = std::string{upload_code::kFolderChanged};
            static_cast<void>(files.write_manifest(manifest_file, manifest_text(manifest)));
            report.out.push_back("kept " + id + ": " + std::string{upload_code::kFolderChanged});
            continue;
        }
        UploadAnswer answer;
        try {
            answer = uploader.upload(manifest.run_id, *parts);
        } catch (...) {
            answer = {false, std::string{upload_code::kInternal}};
        }
        manifest.attempts = std::min(manifest.attempts + 1, kMaxUploadAttempts);
        manifest.last_attempt_at = now_text;
        if (answer.accepted) {
            manifest.sent_at = now_text;
            manifest.last_error.reset();
            manifest.next_attempt_at.reset();
            if (!files.write_manifest(manifest_file, manifest_text(manifest))) {
                error(shown(folder) + ": uploaded, but manifest.json couldn't be written");
                continue;
            }
            --report.queued;
            move_to_sent("sent");
            continue;
        }
        manifest.last_error = is_upload_error(answer.error) ? answer.error
                                                            : std::string{upload_code::kInternal};
        manifest.next_attempt_at = outbox_time_text(now + upload_retry_delay(manifest.attempts));
        if (!files.write_manifest(manifest_file, manifest_text(manifest))) {
            error(shown(manifest_file) + ": could not be written");
        }
        report.out.push_back(std::format("kept {}: {}; attempt {}, next at {}", id,
                                         *manifest.last_error, manifest.attempts,
                                         *manifest.next_attempt_at));
    }
    return report;
}

} // namespace rp
