#pragma once

// W6.3 (#183; docs/decisions.md 2026-10-14, W6.3 and W6.2, points 3 to 5):
// a random file's content checked against the backup's own copy. Before the
// restore the pipeline marks every random file whose name has a content rule
// (content_rule) as wanting its content; the connector exports those files'
// bytes from the backup into a ContentHasher, which keeps their hashes and
// nothing else; once restore_sample returns, and before anything is read back,
// add_backup_content raises each exported file's expectation from `metadata`
// to `backup_content`. A file whose export gave nothing stays `metadata`
// (checked by name and size as before) with its export's word: an export's
// own fault is never a fail and never an error by itself.

#include <rp/canary_manifest.hpp>
#include <rp/connector.hpp>
#include <rp/expected_set.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp::verification {

// The rule a file's content is compared by, from its name alone: office-v1
// for a name ending, ASCII case-insensitively, in .docx or .xlsx (what
// office-v1 reads); none for every other name SharePoint rewrites
// (rp::is_rewritten_office_file: pptx, legacy Office, the macro and template
// types), which has no content rule yet; bytes for every other name.
std::optional<sampling::ContentRule> content_rule(std::string_view name);

// What the hasher kept of one exported file.
struct ContentDigest {
    std::int64_t size_bytes = 0;
    std::string sha256;    // of the bytes, lower-case hex
    std::string office_v1; // office-v1, for a docx or xlsx that is a valid package
    bool office_invalid = false; // a docx or xlsx office-v1 refused
};

// (kind, index in the kind's selectors) -> the digest.
using ContentDigests = std::map<std::pair<connector::ItemKind, std::size_t>, ContentDigest>;

// The sink the pipeline hands restore_sample: hashes each exported file's
// bytes as it comes (SHA-256, and office-v1 for a name content_rule gives
// office-v1), keeps the digests and drops the bytes. Thread-safe: the
// connector calls it on its own thread. A kind or index the spec has no file
// for is std::logic_error, which restore_sample turns into a stop with
// nothing restored.
class ContentHasher final : public connector::IContentSink {
public:
    // The names of the spec's SharePoint and OneDrive selectors, in order.
    ContentHasher(std::vector<std::string> sharepoint_names,
                  std::vector<std::string> onedrive_names);

    void on_content(connector::ItemKind kind, std::size_t index, std::string_view bytes) override;

    ContentDigests digests() const;

private:
    std::vector<std::string> sharepoint_;
    std::vector<std::string> onedrive_;
    mutable std::mutex mutex_;
    ContentDigests digests_;
};

// Pure. Marks want_content on every random file selector of `spec` whose name
// has a content rule; canaries (the first canary_ids of each kind, the
// manifest's hash) and mails never. Answers how many were marked.
std::size_t mark_wanted(connector::RestoreSpec& spec, const sampling::SampleRecord& record);

// Pure. Raises `expected`'s random files from the restore's exports and
// their digests, before the read back: every random file gets its export's
// word (export_word): "no_rule" for a name without a content rule (never
// asked); the export's outcome otherwise (connector::to_string); an exported
// file with its digest becomes backup_content (bytes: the export's SHA-256
// and size; office-v1: its office-v1 and no size), and an exported docx or
// xlsx office-v1 refused stays metadata with "invalid_package". Throws
// std::logic_error ("backup content: ...", by position, never a value) when
// the facts don't add up: an export for a file that isn't a random one of
// the set, or for one without a content rule; a random file with a rule
// and no export; an exported file without its digest; a digest without an
// export; an item already backup_content. Nothing is changed then.
void add_backup_content(ExpectedSet& expected, const connector::RestoreResult& result,
                        const ContentDigests& digests);

// The line `rpworker test` prints after the restore's tables when content
// was asked for: "content exports: <exported> of <asked> file(s) exported
// from the backup" and, when some weren't, " (<word> <n>, ...)" in the
// export words' order; empty when nothing was asked.
std::string content_exports_line(const connector::RestoreResult& result);

} // namespace rp::verification
