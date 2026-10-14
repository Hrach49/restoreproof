#include <rp/backup_content.hpp>

#include <rp/office_v1.hpp>
#include <rp/sha256.hpp>

#include "office_files.hpp"
#include "text_util.hpp"

#include <algorithm>
#include <format>
#include <stdexcept>

namespace rp::verification {

namespace {

using connector::ContentOutcome;
using connector::ItemKind;
using sampling::ContentRule;

std::string kind_name(ItemKind kind)
{
    return std::string{connector::to_string(kind)};
}

// "docx" or "xlsx": office-v1's file type for a name it reads.
std::string_view office_type(std::string_view name)
{
    return ascii_ends_with_i(name, ".docx") ? "docx" : "xlsx";
}

[[noreturn]] void refuse(const std::string& why)
{
    throw std::logic_error("backup content: " + why);
}

} // namespace

std::optional<ContentRule> content_rule(std::string_view name)
{
    // office-v1 reads these only. A name that is only an extension (".docx")
    // is no package by office_files.hpp's rule, and is read by its bytes.
    if (name.size() > 5 && (ascii_ends_with_i(name, ".docx") || ascii_ends_with_i(name, ".xlsx"))) {
        return ContentRule::office_v1;
    }
    if (is_rewritten_office_file(name)) {
        return std::nullopt;
    }
    return ContentRule::bytes;
}

ContentHasher::ContentHasher(std::vector<std::string> sharepoint_names,
                             std::vector<std::string> onedrive_names)
    : sharepoint_(std::move(sharepoint_names)), onedrive_(std::move(onedrive_names))
{
}

void ContentHasher::on_content(ItemKind kind, std::size_t index, std::string_view bytes)
{
    const std::vector<std::string>* names = kind == ItemKind::sharepoint ? &sharepoint_
                                            : kind == ItemKind::onedrive ? &onedrive_
                                                                         : nullptr;
    if (names == nullptr || index >= names->size()) {
        refuse("content for " + kind_name(kind) + " item " + std::to_string(index) +
               ", which the spec doesn't have");
    }
    const std::string& name = (*names)[index];
    ContentDigest digest;
    digest.size_bytes = static_cast<std::int64_t>(bytes.size());
    digest.sha256 = sha256_hex(bytes);
    if (content_rule(name) == ContentRule::office_v1) {
        try {
            digest.office_v1 = office_v1_sha256(bytes, office_type(name));
        } catch (const OfficeContentError&) {
            // Its text names a part inside a tenant file: kept as a flag only.
            digest.office_invalid = true;
        }
    }
    const std::lock_guard lock(mutex_);
    digests_[{kind, index}] = std::move(digest);
}

ContentDigests ContentHasher::digests() const
{
    const std::lock_guard lock(mutex_);
    return digests_;
}

std::size_t mark_wanted(connector::RestoreSpec& spec, const sampling::SampleRecord& record)
{
    std::size_t marked = 0;
    for (std::size_t i = record.sharepoint.canary_ids.size(); i < spec.sharepoint.size(); ++i) {
        if (content_rule(spec.sharepoint[i].name)) {
            spec.sharepoint[i].want_content = true;
            ++marked;
        }
    }
    for (std::size_t i = record.onedrive.canary_ids.size(); i < spec.onedrive.size(); ++i) {
        if (content_rule(spec.onedrive[i].name)) {
            spec.onedrive[i].want_content = true;
            ++marked;
        }
    }
    return marked;
}

void add_backup_content(ExpectedSet& expected, const connector::RestoreResult& result,
                        const ContentDigests& digests)
{
    // Each file item's place among its kind's selectors: the set is in spec order.
    struct Place {
        std::size_t item = 0;
        bool random = false;
    };
    std::map<std::pair<ItemKind, std::size_t>, Place> places;
    std::size_t sharepoint = 0;
    std::size_t onedrive = 0;
    for (std::size_t i = 0; i < expected.items.size(); ++i) {
        const ExpectedItem& item = expected.items[i];
        if (item.kind == ItemKind::mail) {
            continue;
        }
        std::size_t& n = item.kind == ItemKind::sharepoint ? sharepoint : onedrive;
        places[{item.kind, n++}] = {i, item.source == ItemSource::random};
    }

    std::map<std::size_t, const connector::ContentExport*> by_item;
    for (std::size_t j = 0; j < result.content.size(); ++j) {
        const connector::ContentExport& e = result.content[j];
        const auto place = places.find({e.kind, e.index});
        if (place == places.end() || !place->second.random) {
            refuse("export " + std::to_string(j) + " is for no random file of the set");
        }
        const ExpectedItem& item = expected.items[place->second.item];
        if (!item.file || !content_rule(item.file->name)) {
            refuse("export " + std::to_string(j) + " is for a file without a content rule");
        }
        if (!by_item.emplace(place->second.item, &e).second) {
            refuse("export " + std::to_string(j) + " is a second one for its file");
        }
        if ((e.outcome == ContentOutcome::exported) != digests.contains({e.kind, e.index})) {
            refuse("export " + std::to_string(j) +
                   (e.outcome == ContentOutcome::exported ? " has no digest"
                                                          : " has a digest but wasn't exported"));
        }
    }
    for (const auto& [key, digest] : digests) {
        const auto place = places.find(key);
        if (place == places.end() || !by_item.contains(place->second.item)) {
            refuse("a digest of " + kind_name(key.first) + " item " +
                   std::to_string(key.second) + " has no export");
        }
    }

    // Every check above came first: nothing is changed unless all hold.
    std::vector<ExpectedItem> raised = expected.items;
    for (const auto& [key, place] : places) {
        if (!place.random) {
            continue;
        }
        ExpectedItem& item = raised[place.item];
        if (item.expected_kind != ExpectedKind::metadata) {
            refuse("item " + std::to_string(place.item) + " isn't metadata");
        }
        const std::optional<ContentRule> rule = content_rule(item.file->name);
        const auto found = by_item.find(place.item);
        if (!rule) {
            item.export_word = "no_rule";
            continue;
        }
        if (found == by_item.end()) {
            refuse("item " + std::to_string(place.item) + " has a content rule and no export");
        }
        const connector::ContentExport& e = *found->second;
        if (e.outcome != ContentOutcome::exported) {
            item.export_word = std::string{connector::to_string(e.outcome)};
            continue;
        }
        const ContentDigest& digest = digests.at(key);
        if (*rule == ContentRule::bytes) {
            item.sha256 = digest.sha256;
            item.sha256_rule = "bytes";
            item.file->size_bytes = digest.size_bytes;
        } else if (digest.office_invalid || digest.office_v1.empty()) {
            item.export_word = "invalid_package";
            continue;
        } else {
            item.sha256 = digest.office_v1;
            item.sha256_rule = "office-v1";
            item.file->size_bytes.reset();
        }
        item.expected_kind = ExpectedKind::backup_content;
        item.export_word = "exported";
    }
    expected.items = std::move(raised);
}

std::string content_exports_line(const connector::RestoreResult& result)
{
    if (result.content.empty()) {
        return {};
    }
    std::size_t exported = 0;
    std::map<std::string_view, std::size_t> by_word;
    for (const connector::ContentExport& e : result.content) {
        if (e.outcome == ContentOutcome::exported) {
            ++exported;
        } else {
            ++by_word[connector::to_string(e.outcome)];
        }
    }
    std::string line = std::format("content exports: {} of {} file(s) exported from the backup",
                                   exported, result.content.size());
    std::string counts;
    for (const std::string_view word : export_words()) {
        if (const auto it = by_word.find(word); it != by_word.end()) {
            counts += (counts.empty() ? "" : ", ") + std::string{word} + " " +
                      std::to_string(it->second);
        }
    }
    if (!counts.empty()) {
        line += " (" + counts + ")";
    }
    return line + "\n";
}

} // namespace rp::verification
