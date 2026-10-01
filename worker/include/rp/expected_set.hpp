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
//    Office package, src/office_files.hpp), no hash.
enum class ExpectedKind { manifest, fields, metadata };

// "manifest", "fields" or "metadata".
std::string_view to_string(ExpectedKind kind) noexcept;

enum class ItemSource { canary, random };

// "canary" or "random".
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
    std::optional<std::int64_t> size_bytes; // nullopt: not an expectation (an Office package)
};

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
};

struct ExpectedSet {
    std::string manifest_sha256;
    std::vector<ExpectedItem> items; // in index order
};

// Pure. One ExpectedItem per selector of `selection`, in RestoreSpec order:
// mail canaries, mail random items, SharePoint canaries and random items,
// OneDrive canaries and random items. A canary is `manifest` (a mail: its
// subject, sender address, sent and received times, internet message ID and
// body_sha256 by text-v1; a file: its name, its stored_size for a `bytes`
// file, and content_sha256 by its content_rule); a random mail `fields`
// (subject, received time, and the sender name and sent time when the backup
// listed them); a random file `metadata` (name, and the backup's size unless
// is_office_package). Nothing is built when, in this order:
//  - selection.record.manifest_sha256 isn't manifest.sha256:
//    std::invalid_argument("expected set: the selection wasn't made from this manifest");
//  - a type's selectors aren't its canary_ids and <kind>_random in number:
//    std::invalid_argument("expected set: the <kind> selectors don't match the canaries
//    and random items recorded");
//  - a canary id isn't one of the manifest's canaries of that type:
//    std::logic_error("expected set: canary <n> of <kind> isn't in the manifest"), by
//    position, never quoting the id; or its selector isn't that entry's:
//    "... isn't the manifest's entry";
//  - a random selector isn't its candidate's: std::logic_error("expected set: random
//    item <n> of <kind> isn't the candidate the sampler took").
ExpectedSet build_expected_set(const sampling::Selection& selection,
                               const sampling::CanaryManifest& manifest);

// The result's "expected" object: {"manifest_sha256", "counts": {"manifest",
// "fields", "metadata"} (all three, 0 allowed), "items": [{"index", "kind",
// "source", "expected_kind", "canary_id" or "key", then "subject",
// "sender_address", "sender_name", "sent_at", "received_at",
// "internet_message_id" for a mail or "name", "size_bytes" for a file, and
// "sha256", "sha256_rule"}]}. A key whose value isn't known is left out,
// never null.
nlohmann::json to_json(const ExpectedSet& set);

} // namespace rp::verification
