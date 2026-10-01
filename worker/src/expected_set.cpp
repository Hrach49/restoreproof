#include <rp/expected_set.hpp>

#include "office_files.hpp"

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace rp::verification {

namespace {

using connector::ItemKind;
using nlohmann::json;
using sampling::CanaryFile;
using sampling::CanaryMail;
using sampling::ContentRule;

std::string kind_name(ItemKind kind)
{
    return std::string{connector::to_string(kind)};
}

// Per type, as many selectors as canaries and random candidates recorded, a
// key per random candidate, and the record's counts what the selection holds.
template <typename Selector, typename Candidate>
void check_counts(ItemKind kind, const std::vector<Selector>& selectors,
                  const sampling::KindRecord& record, const std::vector<Candidate>& randoms)
{
    if (selectors.size() != record.canary_ids.size() + randoms.size() ||
        record.random_keys.size() != randoms.size() ||
        std::cmp_not_equal(record.canary_wanted, record.canary_ids.size()) ||
        std::cmp_not_equal(record.random_taken, randoms.size())) {
        throw std::invalid_argument("expected set: the " + kind_name(kind) +
                                    " selectors don't match the canaries and random items recorded");
    }
}

template <typename Canary>
const Canary* find_canary(const std::vector<Canary>& canaries, const std::string& id)
{
    for (const Canary& canary : canaries) {
        if (canary.id == id) {
            return &canary;
        }
    }
    return nullptr;
}

ExpectedItem from_canary(const CanaryMail& canary)
{
    ExpectedItem item;
    item.mail = ExpectedMail{canary.subject, canary.sender,     std::nullopt,
                             canary.sent_at, canary.received_at, canary.internet_message_id};
    item.sha256 = canary.body_sha256;
    item.sha256_rule = canary.body_normalization;
    return item;
}

ExpectedItem from_canary(const CanaryFile& canary)
{
    ExpectedItem item;
    const bool bytes = canary.content_rule == ContentRule::bytes;
    // An office-v1 file's stored size is evidence only: SharePoint rewrites it.
    item.file = ExpectedFile{canary.name, bytes ? std::optional{canary.stored_size} : std::nullopt};
    item.sha256 = canary.content_sha256;
    item.sha256_rule = bytes ? "bytes" : "office-v1";
    return item;
}

std::optional<std::string> said(const std::string& text)
{
    return text.empty() ? std::nullopt : std::optional{text};
}

ExpectedItem from_random(const connector::MailCandidate& candidate)
{
    ExpectedItem item;
    item.expected_kind = ExpectedKind::fields;
    item.mail = ExpectedMail{candidate.selector.subject,     std::nullopt,
                             said(candidate.sender_name),    said(candidate.sent_at),
                             candidate.selector.received_at, std::nullopt};
    return item;
}

template <typename FileCandidate>
ExpectedItem from_random(const FileCandidate& candidate)
{
    ExpectedItem item;
    item.expected_kind = ExpectedKind::metadata;
    const std::string& name = candidate.selector.name;
    // A size below 0 is one the backup didn't give: no expectation.
    const bool sized = candidate.size_bytes >= 0 && !is_office_package(name);
    item.file = ExpectedFile{name, sized ? std::optional{candidate.size_bytes} : std::nullopt};
    return item;
}

// One type's items, canaries first, appended to `out` with their index.
template <typename Selector, typename Candidate, typename Canary, typename ToSelector>
void add_kind(ItemKind kind, const std::vector<Selector>& selectors,
              const sampling::KindRecord& record, const std::vector<Candidate>& randoms,
              const std::vector<Canary>& canaries, ToSelector to_selector,
              std::vector<ExpectedItem>& out)
{
    const std::size_t c = record.canary_ids.size();
    for (std::size_t j = 0; j < c; ++j) {
        const std::string where = "expected set: canary " + std::to_string(j) + " of " + kind_name(kind);
        const Canary* canary = find_canary(canaries, record.canary_ids[j]);
        if (canary == nullptr) {
            throw std::logic_error(where + " isn't in the manifest");
        }
        if (!(selectors[j] == to_selector(*canary))) {
            throw std::logic_error(where + " isn't the manifest's entry");
        }
        ExpectedItem item = from_canary(*canary);
        item.source = ItemSource::canary;
        item.expected_kind = ExpectedKind::manifest;
        item.canary_id = canary->id;
        item.kind = kind;
        item.index = out.size();
        out.push_back(std::move(item));
    }
    for (std::size_t j = 0; j < randoms.size(); ++j) {
        if (!(selectors[c + j] == randoms[j].selector) ||
            record.random_keys[j] != sampling::random_key(selectors[c + j])) {
            throw std::logic_error("expected set: random item " + std::to_string(j) + " of " +
                                   kind_name(kind) + " isn't the candidate the sampler took");
        }
        ExpectedItem item = from_random(randoms[j]);
        item.source = ItemSource::random;
        item.random_key = record.random_keys[j];
        item.kind = kind;
        item.index = out.size();
        out.push_back(std::move(item));
    }
}

template <typename T>
void put(json& out, const char* key, const std::optional<T>& value)
{
    if (value) {
        out[key] = *value;
    }
}

void put(json& out, const char* key, const std::string& value)
{
    if (!value.empty()) {
        out[key] = value;
    }
}

bool is_lower_hex_sha256(const std::string& text)
{
    return text.size() == 64 && std::ranges::all_of(text, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

// Why `item` claims what its fields don't hold, or nullptr: each expected
// kind with exactly its source, type and evidence, so no item reads as
// checked against a hash it hasn't.
const char* inconsistency(const ExpectedItem& item, std::size_t position)
{
    if (item.index != position) {
        return "isn't at its index";
    }
    const bool mail = item.kind == ItemKind::mail;
    const bool file = item.kind == ItemKind::sharepoint || item.kind == ItemKind::onedrive;
    if (!mail && !file) {
        return "has an unknown type";
    }
    if (item.mail.has_value() != mail || item.file.has_value() != file) {
        return "doesn't hold its type's fields";
    }
    switch (item.expected_kind) {
    case ExpectedKind::manifest: {
        const bool rule = mail ? item.sha256_rule == "text-v1"
                               : item.sha256_rule == "bytes" || item.sha256_rule == "office-v1";
        if (item.source != ItemSource::canary || item.canary_id.empty() ||
            !item.random_key.empty() || !is_lower_hex_sha256(item.sha256) || !rule) {
            return "is manifest but not a canary with a hash and its rule";
        }
        return nullptr;
    }
    case ExpectedKind::fields:
    case ExpectedKind::metadata:
        if (item.source != ItemSource::random || item.random_key.empty() ||
            !item.canary_id.empty() || !item.sha256.empty() || !item.sha256_rule.empty() ||
            mail != (item.expected_kind == ExpectedKind::fields)) {
            return "is fields or metadata but not a random item of its type without a hash";
        }
        return nullptr;
    }
    return "has an unknown expected kind";
}

json item_json(const ExpectedItem& item)
{
    json out = {
        {"index", item.index},
        {"kind", connector::to_string(item.kind)},
        {"source", to_string(item.source)},
        {"expected_kind", to_string(item.expected_kind)},
    };
    put(out, "canary_id", item.canary_id);
    if (!item.random_key.empty()) {
        out["key"] = item.random_key;
    }
    if (item.mail) {
        out["subject"] = item.mail->subject;
        put(out, "sender_address", item.mail->sender_address);
        put(out, "sender_name", item.mail->sender_name);
        put(out, "sent_at", item.mail->sent_at);
        out["received_at"] = item.mail->received_at;
        put(out, "internet_message_id", item.mail->internet_message_id);
    }
    if (item.file) {
        out["name"] = item.file->name;
        put(out, "size_bytes", item.file->size_bytes);
    }
    put(out, "sha256", item.sha256);
    put(out, "sha256_rule", item.sha256_rule);
    return out;
}

} // namespace

std::string_view to_string(ExpectedKind kind) noexcept
{
    switch (kind) {
    case ExpectedKind::fields:
        return "fields";
    case ExpectedKind::metadata:
        return "metadata";
    case ExpectedKind::manifest:
        return "manifest";
    }
    return "unknown";
}

std::string_view to_string(ItemSource source) noexcept
{
    switch (source) {
    case ItemSource::random:
        return "random";
    case ItemSource::canary:
        return "canary";
    }
    return "unknown";
}

ExpectedSet build_expected_set(const sampling::Selection& selection,
                               const sampling::CanaryManifest& manifest)
{
    const sampling::SampleRecord& record = selection.record;
    if (record.manifest_sha256 != manifest.sha256) {
        throw std::invalid_argument("expected set: the selection wasn't made from this manifest");
    }
    check_counts(ItemKind::mail, selection.mail, record.mail, selection.mail_random);
    check_counts(ItemKind::sharepoint, selection.sharepoint, record.sharepoint,
                 selection.sharepoint_random);
    check_counts(ItemKind::onedrive, selection.onedrive, record.onedrive, selection.onedrive_random);

    ExpectedSet set;
    set.manifest_sha256 = manifest.sha256;
    add_kind(ItemKind::mail, selection.mail, record.mail, selection.mail_random, manifest.mail,
             sampling::to_selector, set.items);
    add_kind(ItemKind::sharepoint, selection.sharepoint, record.sharepoint,
             selection.sharepoint_random, manifest.sharepoint, sampling::to_sharepoint_selector,
             set.items);
    add_kind(ItemKind::onedrive, selection.onedrive, record.onedrive, selection.onedrive_random,
             manifest.onedrive, sampling::to_onedrive_selector, set.items);
    return set;
}

json to_json(const ExpectedSet& set)
{
    std::size_t manifest = 0;
    std::size_t fields = 0;
    std::size_t metadata = 0;
    json items = json::array();
    for (const ExpectedItem& item : set.items) {
        if (const char* why = inconsistency(item, items.size())) {
            throw std::logic_error("expected set: item " + std::to_string(items.size()) + " " + why);
        }
        switch (item.expected_kind) {
        case ExpectedKind::manifest:
            ++manifest;
            break;
        case ExpectedKind::fields:
            ++fields;
            break;
        case ExpectedKind::metadata:
            ++metadata;
            break;
        }
        items.push_back(item_json(item));
    }
    return {
        {"manifest_sha256", set.manifest_sha256},
        {"counts", {{"manifest", manifest}, {"fields", fields}, {"metadata", metadata}}},
        {"items", std::move(items)},
    };
}

} // namespace rp::verification
