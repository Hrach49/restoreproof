#pragma once

// The expected set (W3.1; docs/decisions.md 2026-10-01, W3.1): for every item
// a run samples, what its restored copy should look like and how that
// expectation was obtained, its expected kind, recorded before anything is
// compared. W3.2 compares the restored items with it, W3.3 turns that into a
// status, and the report shows each item's kind so it never claims more than
// was checked.

#include <rp/canary_manifest.hpp>
#include <rp/connector.hpp>
#include <rp/sample_selector.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp::verification {

// How an item's expectation was obtained, one per item, never mixed:
//  - manifest: a canary; the manifest's values, with a content hash;
//  - fields: a random mail; its header as the backup lists it, no hash;
//  - metadata: a random file; its name and the backup's size (none for an
//    Office file SharePoint rewrites, src/office_files.hpp), no hash;
//  - backup_content (W6.3; docs/decisions.md 2026-10-14, W6.3 and W6.2,
//    point 3): a random file whose bytes the backup exported before the
//    restore; its name and the hash of those bytes by its rule, bytes (with
//    the export's size) or office-v1 (without one).
enum class ExpectedKind { manifest, fields, metadata, backup_content };

// "manifest", "fields", "metadata" or "backup_content"; "unknown" for a value
// outside the enum, never one that claims a check.
std::string_view to_string(ExpectedKind kind) noexcept;

enum class ItemSource { canary, random };

// "canary" or "random"; "unknown" for a value outside the enum.
std::string_view to_string(ItemSource source) noexcept;

// Times are "YYYY-MM-DDTHH:MM:SSZ"; nullopt: not an expectation.
struct ExpectedMail {
    std::string subject;
    std::optional<std::string> sender_address;      // canary: the manifest's sender
    std::optional<std::string> sender_name;         // random: Veeam's `from`, when it said
    std::optional<std::string> sent_at;             // the manifest's, or Veeam's when it said
    std::string received_at;
    std::optional<std::string> internet_message_id; // canary only
};

struct ExpectedFile {
    std::string name;
    std::optional<std::int64_t> size_bytes; // nullopt: not an expectation (an Office
                                            // package, or a size the backup didn't give)
};

// Its defaults are a canary's, but to_json writes no item whose fields don't
// hold what its expected kind claims.
struct ExpectedItem {
    std::size_t index = 0; // its position in RestoreSpec and RestoreResult::items
    connector::ItemKind kind = connector::ItemKind::mail;
    ItemSource source = ItemSource::canary;
    ExpectedKind expected_kind = ExpectedKind::manifest;
    std::string canary_id;               // canary only: the manifest's id
    std::vector<std::string> random_key; // random only: the sampler's key (record's random_keys)
    std::optional<ExpectedMail> mail;    // set for kind mail
    std::optional<ExpectedFile> file;    // set for sharepoint and onedrive
    std::string sha256;                  // manifest kind only: lower-case hex
    std::string sha256_rule;             // "text-v1", "bytes" or "office-v1"; empty with sha256
    // W6.3, a random file alone: what became of its export from the backup,
    // one of kExportWords ("exported" for backup_content); empty: not said.
    std::string export_word;
};

// The words of ExpectedItem::export_word, in the order they are counted:
// exported, no_rule, refused, no_answer, size_mismatch, over_cap,
// invalid_package, not_in_backup, budget.
std::vector<std::string_view> export_words();
// The ones a content_export warning names: an export asked for that gave
// nothing (refused, no_answer, size_mismatch, over_cap, invalid_package,
// budget); never no_rule (no export is asked) or not_in_backup (the restore
// result names it) or exported.
bool is_failed_export(std::string_view word) noexcept;

struct ExpectedSet {
    std::string manifest_sha256;
    std::vector<ExpectedItem> items; // in index order
    // The manifest's seeded_at: a restore point taken after it holds every
    // canary (Q3.1). Empty: not known, so no missing canary is the backup's.
    std::string canaries_seeded_at;
    // W6.2: whether the run had canaries (a manifest); without, manifest_sha256
    // is empty and left out of the result, and canaries_seeded_at is empty.
    // False by default, as a run is (W6.3 review, finding 8).
    bool canaries = false;
};

// Pure. One ExpectedItem per selector of `selection`, in RestoreSpec order:
// mail canaries, mail random items, SharePoint canaries and random items,
// OneDrive canaries and random items. `manifest` null (W6.2): the selection
// was made without canaries (record.canaries false, else
// std::invalid_argument("expected set: the selection was made from a manifest
// this call doesn't have")), and every item is a random one's; with one, the
// selection must have been made with canaries (else "expected set: the
// selection was made without canaries"). A canary is `manifest` (a mail: its
// subject, sender address, sent and received times, internet message ID and
// body_sha256 by text-v1; a file: its name, its stored_size for a `bytes`
// file, and content_sha256 by its content_rule); a random mail `fields`
// (subject, received time, and the sender name and sent time when the backup
// listed them); a random file `metadata` (name, and the backup's size unless
// is_rewritten_office_file or the size is below 0, one the backup didn't give). Nothing is built when (the first two for every type
// first, then per type, mail, SharePoint, OneDrive, its canaries and then its
// random items):
//  - selection.record.manifest_sha256 isn't manifest.sha256:
//    std::invalid_argument("expected set: the selection wasn't made from this manifest");
//  - a type's selectors aren't its canary_ids and <kind>_random in number, its
//    random_keys or random_taken aren't as many as <kind>_random, or its
//    canary_wanted isn't as many as its canary_ids:
//    std::invalid_argument("expected set: the <kind> selectors don't match the canaries
//    and random items recorded");
//  - a canary id isn't one of the manifest's canaries of that type:
//    std::logic_error("expected set: canary <n> of <kind> isn't in the manifest"), by
//    position, never quoting the id; or its selector isn't that entry's:
//    "... isn't the manifest's entry";
//  - a random selector isn't its candidate's, or its recorded key isn't the
//    selector's (sampling::random_key): std::logic_error("expected set: random
//    item <n> of <kind> isn't the candidate the sampler took").
ExpectedSet build_expected_set(const sampling::Selection& selection,
                               const sampling::CanaryManifest* manifest);

// The result's "expected" object: {"manifest_sha256" (left out without
// canaries, W6.2), "counts": {"manifest",
// "fields", "metadata", "backup_content"} (all four, 0 allowed), "items": [{"index", "kind",
// "source", "expected_kind", "canary_id" or "key", then "subject",
// "sender_address", "sender_name", "sent_at", "received_at",
// "internet_message_id" for a mail or "name", "size_bytes" for a file, and
// "sha256", "sha256_rule"}]}. A key whose value isn't known is left out,
// never null. Nothing is written, std::logic_error("expected set: item <n>
// <why>"), when an item isn't at its index, or its expected kind isn't
// backed by its fields: `manifest` only for a canary with a canary_id, no
// key, a lower-case hex sha256 and its type's rule (text-v1 for a mail,
// bytes or office-v1 for a file); `fields` only for a random mail and
// `metadata` only for a random file, each with a key and no canary_id or
// hash; a mail holds `mail` and a file `file`, never both; and for
// `canaries` with an empty manifest_sha256.
nlohmann::json to_json(const ExpectedSet& set);

} // namespace rp::verification
