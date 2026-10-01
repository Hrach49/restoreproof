#pragma once

// The checker (W3.2; docs/decisions.md 2026-10-01, W3.2; docs/verification.md,
// "Comparing"): what became of each expected item (rp/expected_set.hpp) in the
// restore targets. `rpworker restore` lists the targets once before the
// restore (the before snapshot) and once after it, hashing (the after read),
// through TargetReader; check() then matches and compares in memory, pure: it
// never calls Graph. This run's copies are the new ones: a mail whose Graph ID
// wasn't there before, a file that wasn't there or whose cTag moved. An
// infrastructure failure reading a target makes its items `error`, never
// `missing` or `mismatch`. W3.3 turns the outcomes into a status.

#include <rp/connector.hpp>
#include <rp/expected_set.hpp>
#include <rp/graph_targets.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace rp::verification {

// What the check found for one expected item:
//  - match: a copy of this run's was found and every field the expectation
//    carries agrees;
//  - mismatch: a copy was found and at least one field doesn't agree;
//  - missing: no copy of this run's that another item hadn't claimed; for a
//    file, no earlier run's copy of its name either. A mail whose only copies
//    are earlier runs' is missing: an earlier mail can't be told from none;
//  - error: the item couldn't be checked: its target couldn't be read, or,
//    for a file, only an earlier run's copy of its name is there
//    (stale_target). Never a mismatch.
enum class CheckOutcome { match, mismatch, missing, error };

// "match", "mismatch", "missing" or "error"; "unknown" for a value outside the enum.
std::string_view to_string(CheckOutcome outcome) noexcept;

// office-v1 of one restored file (rp/office_v1.hpp): exactly one of the two set.
struct OfficeHash {
    std::string sha256; // lower-case hex
    std::string error;  // the OfficeContentError's message: not a valid package
};

// One read of one target type: its items, or the infrastructure failure that stopped it.
struct TargetRead {
    std::vector<graph::FoundItem> items;
    // Empty: read fine. Else what stopped it (read_error_code): graph_auth,
    // graph_permission, graph_transient, target_guard or graph.
    std::string error_code;
    // After read only: file ID -> its office-v1 result, for each docx or xlsx
    // (office_hook).
    std::map<std::string, OfficeHash> office;
};

struct TargetsRead {
    TargetRead mail;
    TargetRead sharepoint;
    TargetRead onedrive;
};

// What was in the targets before the restore: each mail's Graph ID, and each
// file's ID with its cTag (nullopt: Graph gave none).
struct TargetSnapshot {
    std::set<std::string> mail;
    std::map<std::string, std::optional<std::string>> sharepoint;
    std::map<std::string, std::optional<std::string>> onedrive;
};

// The before snapshot of a read.
TargetSnapshot snapshot_of(const TargetsRead& before);

// Whether a file of the after read is this run's copy: its ID wasn't in
// `before`'s snapshot of its type (FoundItem::type), or its cTag moved (a
// restore merged a new version into a same-named file). A cTag unknown on
// either side can't show a move: an earlier run's copy. Throws
// std::logic_error for a mail.
bool is_new_file(const TargetSnapshot& before, const graph::FoundItem& file);

// TargetReaderOptions::hash_file for the after read: true for a file that is
// this run's copy (is_new_file) and whose name has the name_key of an expected
// file of its type that carries a hash or a size, so an earlier run's
// leftover, a file nobody expects, or a random Office file (nothing of its
// bytes compared) is never downloaded. Keeps its own copy of what it needs; false for a mail.
std::function<bool(const graph::FoundItem&)> hash_filter(const ExpectedSet& expected,
                                                         const TargetSnapshot& before);

// The error_code of an exception thrown while reading a target:
// graph::WrongTargetError "target_guard" (before GraphError: it is one),
// graph::AuthError "graph_auth", graph::PermissionError "graph_permission",
// graph::TransientError "graph_transient", any other graph::GraphError and an
// rp::ConfigError (a graph::CertificateError) "graph". Rethrows anything else,
// and std::invalid_argument for a null `error`.
std::string read_error_code(std::exception_ptr error);

// TargetReaderOptions::on_file for the after read: office-v1 of each file
// whose name ends, ASCII case-insensitively, in .docx or .xlsx, into
// `after`'s TargetRead of the file's type (FoundItem::type) under its ID. An
// OfficeContentError is kept as OfficeHash::error, never thrown; a file of
// another name is left alone. `after` must outlive the hook. Throws
// std::logic_error for a mail.
std::function<void(const graph::FoundItem&, std::string_view)> office_hook(TargetsRead& after);

// What the check found for one expected item.
struct ItemCheck {
    std::size_t index = 0; // the expected item's, and its RestoreResult::items position
    connector::ItemKind kind = connector::ItemKind::mail;
    CheckOutcome outcome = CheckOutcome::missing;
    bool found = false; // a copy of this run's was compared
    // The fields that didn't agree, in this order: subject, sender_address,
    // sender_name, sent_at, received_at, internet_message_id, size_bytes, sha256.
    std::vector<std::string> mismatches;
    // One line; empty for a match. Never a tenant value (subject, name, sender,
    // address, ID), but an office-v1 refusal's message, which names a part.
    std::string reason;
    // More than one copy of this run's matched; the newest was compared.
    // Never changes the outcome (W3.3 decides).
    bool duplicate = false;
    std::size_t copies = 0;  // this run's copies that matched the lookup
    std::string graph_id;    // the copy compared; never written to JSON
    std::int64_t ms = 0;     // the copy's FoundItem::read_ms + this item's comparison
    std::string error_code;  // outcome error only: the read's code, or "stale_target"
};

struct CheckResult {
    std::vector<ItemCheck> items; // one per expected item, in its order
    // Items in the after read that are earlier runs' copies, per target: ignored.
    std::size_t stale_mail = 0;
    std::size_t stale_sharepoint = 0;
    std::size_t stale_onedrive = 0;
};

// Pure. One ItemCheck per expected item, in order:
//  - a type whose after read failed (error_code set): each of its items is
//    `error` with that code, "the <type> restore target couldn't be read
//    (<code>)"; the other types are still checked;
//  - a canary mail: this run's mails with its internet_message_id, byte-equal,
//    or else those with its subject (internet_message_id then a mismatch);
//    canaries go first, in index order;
//  - a random mail: this run's mails with its subject;
//  - a file: this run's files of its own target whose name is the same
//    (rp::same_name); none, but an earlier run's copy of that name: `error`
//    stale_target; none at all: `missing`;
//  - after the canary mails, every other item in index order; each item
//    claims the copies it matched, so a copy counts for one item only, and an
//    item that finds only claimed copies looks as if it found none;
//  - several copies: the newest (a mail's created_at, a file's modified_at;
//    one that doesn't read is oldest; a tie goes to the greater ID) is
//    compared, duplicate set.
// Compared only when the expectation carries it: subject byte-equal;
// sender_address with FoundItem::sender, ASCII case-insensitive; sender_name
// with without_controls(FoundItem::sender_name), byte-equal; sent_at and
// received_at within 120 s either way (rp::parse_veeam_time; a found value
// missing or not a time is a mismatch); internet_message_id byte-equal;
// size_bytes with the downloaded count; sha256 by its rule: text-v1 and bytes
// with FoundItem::sha256 of that rule, office-v1 with after's office entry
// (an OfficeHash error is a mismatch on sha256: the restored package is
// broken). `clock` (null: steady_clock::now) times each comparison.
// Throws std::invalid_argument when the expected items aren't at indexes 0 to
// n-1 in order, and std::logic_error for an expected item that isn't one
// build_expected_set makes (a mail without `mail`, a time that doesn't read,
// a hash rule it doesn't know).
CheckResult check(const ExpectedSet& expected, const TargetSnapshot& before,
                  const TargetsRead& after,
                  std::function<std::chrono::steady_clock::time_point()> clock = {});

// The result's "check" object: {"counts": {"match", "mismatch", "missing",
// "error"} (all four, 0 allowed), "stale_copies": {"mail", "sharepoint",
// "onedrive"}, "items": [{"index", "outcome", "found", then "mismatches"
// (when any), "reason" (unless a match), "duplicate": true and "copies" (only
// for a duplicate), "error_code" (for an error), "ms" (when found)}]}. Never a
// found value nor a Graph ID. Nothing is written, std::logic_error("check:
// item <n> <why>"), when an item isn't at its index or its fields contradict
// its outcome: a match found without mismatches, reason or code; a mismatch
// found with mismatches and a reason, without a code; missing not found,
// without mismatches or code, with a reason; an error not found, without
// mismatches, with a code and a reason; a duplicate found with 2 copies or more.
nlohmann::json to_json(const CheckResult& result);

} // namespace rp::verification
