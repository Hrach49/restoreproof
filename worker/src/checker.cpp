#include <rp/checker.hpp>

#include <rp/config.hpp>
#include <rp/graph_errors.hpp>
#include <rp/office_v1.hpp>
#include <rp/target_guard_graph.hpp>

#include "name_key.hpp"
#include "text_util.hpp"
#include "veeam_time.hpp"

#include <algorithm>
#include <iterator>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace rp::verification {

namespace {

using connector::ItemKind;
using graph::FoundItem;
using nlohmann::json;

// How far a restored copy's time may be from the expected one, either way:
// the issue's 2 minutes (docs/decisions.md 2026-10-01, W3.2 point 2).
constexpr std::chrono::seconds kTimeTolerance{120};

constexpr std::string_view kTextV1 = "text-v1";
constexpr std::string_view kBytes = "bytes";

std::string kind_name(ItemKind kind)
{
    return std::string{connector::to_string(kind)};
}

const TargetRead& read_of(const TargetsRead& reads, ItemKind kind)
{
    switch (kind) {
    case ItemKind::sharepoint:
        return reads.sharepoint;
    case ItemKind::onedrive:
        return reads.onedrive;
    case ItemKind::mail:
        break;
    }
    return reads.mail;
}

const std::map<std::string, std::optional<std::string>>& files_before(const TargetSnapshot& before,
                                                                      ItemKind kind)
{
    return kind == ItemKind::sharepoint ? before.sharepoint : before.onedrive;
}

// Whether a file of the after read is this run's: not there before, or its
// cTag moved (a restore merged a new version into a same-named file). A cTag
// unknown on either side can't show a move: an earlier run's copy.
bool file_is_new(const FoundItem& file,
                 const std::map<std::string, std::optional<std::string>>& before)
{
    const auto it = before.find(file.id);
    if (it == before.end()) {
        return true;
    }
    return it->second && file.ctag && *it->second != *file.ctag;
}

// One type's after read split into this run's copies and earlier ones.
struct Copies {
    std::vector<const FoundItem*> fresh;
    std::vector<const FoundItem*> stale;
};

Copies split(const TargetSnapshot& before, const TargetsRead& after, ItemKind kind)
{
    Copies copies;
    const TargetRead& read = read_of(after, kind);
    if (!read.error_code.empty()) {
        return copies;
    }
    for (const FoundItem& item : read.items) {
        const bool fresh = kind == ItemKind::mail ? !before.mail.contains(item.id)
                                                  : file_is_new(item, files_before(before, kind));
        (fresh ? copies.fresh : copies.stale).push_back(&item);
    }
    return copies;
}

// An expected time: the expected set's own form, so one that doesn't read is
// a bug, never a mismatch.
VeeamTime expected_time(const std::string& text)
{
    const std::optional<VeeamTime> time = parse_veeam_time(text);
    if (!time) {
        throw std::logic_error("check: an expected time isn't a time");
    }
    return *time;
}

bool time_agrees(const std::string& expected, const std::optional<std::string>& found)
{
    const VeeamTime want = expected_time(expected);
    const std::optional<VeeamTime> got = found ? parse_veeam_time(*found) : std::nullopt;
    if (!got) {
        return false;
    }
    const auto off = *got > want ? *got - want : want - *got;
    return off <= kTimeTolerance;
}

// The newest copy: by `when` (a time that doesn't read is the oldest), then
// the greater ID.
const FoundItem* newest(const std::vector<const FoundItem*>& copies,
                        std::optional<std::string> FoundItem::*when)
{
    const auto key = [when](const FoundItem* item) {
        const std::optional<VeeamTime> time =
            item->*when ? parse_veeam_time(*(item->*when)) : std::nullopt;
        return std::tuple{time.has_value(), time.value_or(VeeamTime{}), item->id};
    };
    return *std::ranges::max_element(copies, {}, key);
}

// The comparison of one copy with its expectation: the mismatched fields, in
// ItemCheck's order, and what to add to the reason.
struct Comparison {
    std::vector<std::string> mismatches;
    std::string note;
};

void compare_mail(const ExpectedMail& want, const FoundItem& got, Comparison& out)
{
    const auto differs = [&](bool agrees, const char* field) {
        if (!agrees) {
            out.mismatches.emplace_back(field);
        }
    };
    differs(got.subject && *got.subject == want.subject, "subject");
    if (want.sender_address) {
        differs(got.sender && ascii_iequals(*got.sender, *want.sender_address), "sender_address");
    }
    if (want.sender_name) {
        differs(got.sender_name && without_controls(*got.sender_name) == *want.sender_name,
                "sender_name");
    }
    if (want.sent_at) {
        differs(time_agrees(*want.sent_at, got.sent_at), "sent_at");
    }
    differs(time_agrees(want.received_at, got.received_at), "received_at");
    if (want.internet_message_id) {
        differs(got.internet_message_id && *got.internet_message_id == *want.internet_message_id,
                "internet_message_id");
    }
}

// The sha256 comparison, by the expectation's rule.
void compare_hash(const ExpectedItem& want, const FoundItem& got, const TargetRead& read,
                  Comparison& out)
{
    if (want.sha256.empty()) {
        return;
    }
    bool agrees = false;
    if (want.sha256_rule == kTextV1 || want.sha256_rule == kBytes) {
        agrees = got.sha256_rule == want.sha256_rule && got.sha256 == want.sha256;
    } else if (want.sha256_rule == kOfficeV1) {
        const auto it = read.office.find(got.id);
        if (it != read.office.end() && !it->second.error.empty()) {
            out.note = "; the restored package isn't valid office-v1 input (" +
                       one_line(it->second.error) + ")";
        } else {
            agrees = it != read.office.end() && it->second.sha256 == want.sha256;
        }
    } else {
        throw std::logic_error("check: an expected hash rule it doesn't know");
    }
    if (!agrees) {
        out.mismatches.emplace_back("sha256");
    }
}

Comparison compare(const ExpectedItem& want, const FoundItem& got, const TargetRead& read)
{
    Comparison out;
    if (want.kind == ItemKind::mail) {
        compare_mail(*want.mail, got, out);
    } else if (want.file->size_bytes &&
               !(got.size_bytes && std::cmp_equal(*got.size_bytes, *want.file->size_bytes))) {
        out.mismatches.emplace_back("size_bytes");
    }
    compare_hash(want, got, read, out);
    return out;
}

std::string joined(const std::vector<std::string>& names)
{
    std::string text;
    for (const std::string& name : names) {
        text += (text.empty() ? "" : ", ") + name;
    }
    return text;
}

// The expected item is one build_expected_set makes: a mail with `mail`, a
// file with `file`.
void check_shape(const ExpectedItem& item)
{
    if (item.kind == ItemKind::mail ? !item.mail : !item.file) {
        throw std::logic_error("check: expected item " + std::to_string(item.index) +
                               " doesn't hold its type's fields");
    }
}

class Checker {
public:
    Checker(const TargetSnapshot& before, const TargetsRead& after,
            std::function<std::chrono::steady_clock::time_point()> clock)
        : after_(after), clock_(std::move(clock)),
          copies_{{ItemKind::mail, split(before, after, ItemKind::mail)},
                  {ItemKind::sharepoint, split(before, after, ItemKind::sharepoint)},
                  {ItemKind::onedrive, split(before, after, ItemKind::onedrive)}}
    {
    }

    std::size_t stale(ItemKind kind) const { return copies_.at(kind).stale.size(); }

    ItemCheck check(const ExpectedItem& want)
    {
        ItemCheck out;
        out.index = want.index;
        out.kind = want.kind;
        const TargetRead& read = read_of(after_, want.kind);
        if (!read.error_code.empty()) {
            out.outcome = CheckOutcome::error;
            out.error_code = read.error_code;
            out.reason =
                "the " + kind_name(want.kind) + " restore target couldn't be read (" + read.error_code + ")";
            return out;
        }
        const std::vector<const FoundItem*> found = lookup(want);
        if (found.empty()) {
            if (want.kind != ItemKind::mail && has_stale_name(want)) {
                out.outcome = CheckOutcome::error;
                out.error_code = "stale_target";
                out.reason = "only an earlier run's copy is in the target";
            } else {
                out.outcome = CheckOutcome::missing;
                out.reason = "no restored copy found";
            }
            return out;
        }
        const auto started = now();
        const FoundItem& copy = *newest(found, want.kind == ItemKind::mail ? &FoundItem::created_at
                                                                           : &FoundItem::modified_at);
        const Comparison comparison = compare(want, copy, read);
        out.found = true;
        out.graph_id = copy.id;
        out.copies = found.size();
        out.duplicate = found.size() > 1;
        out.mismatches = comparison.mismatches;
        if (out.mismatches.empty()) {
            out.outcome = CheckOutcome::match;
        } else {
            out.outcome = CheckOutcome::mismatch;
            out.reason = "fields did not match: " + joined(out.mismatches) + comparison.note;
        }
        out.ms = copy.read_ms +
                 std::chrono::duration_cast<std::chrono::milliseconds>(now() - started).count();
        return out;
    }

private:
    std::chrono::steady_clock::time_point now() const
    {
        return clock_ ? clock_() : std::chrono::steady_clock::now();
    }

    // This run's copies the item matches; a canary mail claims them.
    std::vector<const FoundItem*> lookup(const ExpectedItem& want)
    {
        std::vector<const FoundItem*> found;
        const std::vector<const FoundItem*>& fresh = copies_.at(want.kind).fresh;
        if (want.kind != ItemKind::mail) {
            std::ranges::copy_if(fresh, std::back_inserter(found), [&](const FoundItem* item) {
                return item->name && same_name(*item->name, want.file->name);
            });
            return found;
        }
        const ExpectedMail& mail = *want.mail;
        const auto unclaimed = [&](const FoundItem* item) { return !claimed_.contains(item->id); };
        if (mail.internet_message_id) {
            std::ranges::copy_if(fresh, std::back_inserter(found), [&](const FoundItem* item) {
                return unclaimed(item) && item->internet_message_id == mail.internet_message_id;
            });
        }
        if (found.empty()) {
            std::ranges::copy_if(fresh, std::back_inserter(found), [&](const FoundItem* item) {
                return unclaimed(item) && item->subject == mail.subject;
            });
        }
        if (want.source == ItemSource::canary) {
            for (const FoundItem* item : found) {
                claimed_.insert(item->id);
            }
        }
        return found;
    }

    bool has_stale_name(const ExpectedItem& want) const
    {
        return std::ranges::any_of(copies_.at(want.kind).stale, [&](const FoundItem* item) {
            return item->name && same_name(*item->name, want.file->name);
        });
    }

    const TargetsRead& after_;
    std::function<std::chrono::steady_clock::time_point()> clock_;
    std::map<ItemKind, Copies> copies_;
    std::set<std::string> claimed_; // mail Graph IDs a canary matched
};

// Why an item's fields contradict its outcome; null when they don't.
const char* inconsistency(const ItemCheck& item, std::size_t at)
{
    if (item.index != at) {
        return "isn't at its index";
    }
    if (item.duplicate && (!item.found || item.copies < 2)) {
        return "is a duplicate without two copies found";
    }
    const bool has_code = !item.error_code.empty();
    const bool has_reason = !item.reason.empty();
    const bool has_mismatches = !item.mismatches.empty();
    switch (item.outcome) {
    case CheckOutcome::match:
        return item.found && !has_mismatches && !has_reason && !has_code
                   ? nullptr
                   : "is a match with something that isn't";
    case CheckOutcome::mismatch:
        return item.found && has_mismatches && has_reason && !has_code
                   ? nullptr
                   : "is a mismatch without what didn't match";
    case CheckOutcome::missing:
        return !item.found && !has_mismatches && has_reason && !has_code
                   ? nullptr
                   : "is missing with something found";
    case CheckOutcome::error:
        return !item.found && !has_mismatches && has_reason && has_code
                   ? nullptr
                   : "is an error without its code";
    }
    return "has an outcome outside the enum";
}

json item_json(const ItemCheck& item)
{
    json out = {{"index", item.index}, {"outcome", to_string(item.outcome)}, {"found", item.found}};
    if (!item.mismatches.empty()) {
        out["mismatches"] = item.mismatches;
    }
    if (!item.reason.empty()) {
        out["reason"] = item.reason;
    }
    if (item.duplicate) {
        out["duplicate"] = true;
        out["copies"] = item.copies;
    }
    if (!item.error_code.empty()) {
        out["error_code"] = item.error_code;
    }
    if (item.found) {
        out["ms"] = item.ms;
    }
    return out;
}

} // namespace

std::string_view to_string(CheckOutcome outcome) noexcept
{
    switch (outcome) {
    case CheckOutcome::match:
        return "match";
    case CheckOutcome::mismatch:
        return "mismatch";
    case CheckOutcome::missing:
        return "missing";
    case CheckOutcome::error:
        return "error";
    }
    return "unknown";
}

TargetSnapshot snapshot_of(const TargetsRead& before)
{
    TargetSnapshot snapshot;
    for (const FoundItem& item : before.mail.items) {
        snapshot.mail.insert(item.id);
    }
    for (const FoundItem& item : before.sharepoint.items) {
        snapshot.sharepoint.emplace(item.id, item.ctag);
    }
    for (const FoundItem& item : before.onedrive.items) {
        snapshot.onedrive.emplace(item.id, item.ctag);
    }
    return snapshot;
}

std::string read_error_code(std::exception_ptr error)
{
    if (!error) {
        throw std::invalid_argument("read_error_code: no exception");
    }
    try {
        std::rethrow_exception(error);
    } catch (const graph::WrongTargetError&) {
        return "target_guard";
    } catch (const graph::AuthError&) {
        return "graph_auth";
    } catch (const graph::PermissionError&) {
        return "graph_permission";
    } catch (const graph::TransientError&) {
        return "graph_transient";
    } catch (const graph::GraphError&) {
        return "graph";
    } catch (const ConfigError&) {
        return "graph";
    }
}

std::function<void(const FoundItem&, std::string_view)> office_hook(TargetsRead& after)
{
    return [&after](const FoundItem& file, std::string_view bytes) {
        TargetRead* read = nullptr;
        switch (file.type) {
        case graph::ItemType::sharepoint:
            read = &after.sharepoint;
            break;
        case graph::ItemType::onedrive:
            read = &after.onedrive;
            break;
        case graph::ItemType::mail:
            break;
        }
        if (!read) {
            throw std::logic_error("office_hook: a mail has no file bytes");
        }
        const std::string name = file.name.value_or("");
        const std::string_view type = ascii_ends_with_i(name, ".docx")   ? "docx"
                                      : ascii_ends_with_i(name, ".xlsx") ? "xlsx"
                                                                         : "";
        if (type.empty()) {
            return;
        }
        OfficeHash hash;
        try {
            hash.sha256 = office_v1_sha256(bytes, type);
        } catch (const OfficeContentError& e) {
            hash.error = e.what();
        }
        read->office[file.id] = std::move(hash);
    };
}

CheckResult check(const ExpectedSet& expected, const TargetSnapshot& before,
                  const TargetsRead& after,
                  std::function<std::chrono::steady_clock::time_point()> clock)
{
    for (std::size_t i = 0; i < expected.items.size(); ++i) {
        if (expected.items[i].index != i) {
            throw std::invalid_argument("check: the expected items aren't in index order");
        }
        check_shape(expected.items[i]);
    }
    Checker checker(before, after, std::move(clock));
    CheckResult result;
    result.items.resize(expected.items.size());
    // Canary mails first, so they claim their copies before a random mail
    // with the same subject looks.
    for (const bool canaries : {true, false}) {
        for (const ExpectedItem& item : expected.items) {
            const bool canary_mail =
                item.kind == ItemKind::mail && item.source == ItemSource::canary;
            if (canary_mail == canaries) {
                result.items[item.index] = checker.check(item);
            }
        }
    }
    result.stale_mail = checker.stale(ItemKind::mail);
    result.stale_sharepoint = checker.stale(ItemKind::sharepoint);
    result.stale_onedrive = checker.stale(ItemKind::onedrive);
    return result;
}

json to_json(const CheckResult& result)
{
    std::map<CheckOutcome, std::size_t> counts;
    json items = json::array();
    for (const ItemCheck& item : result.items) {
        if (const char* why = inconsistency(item, items.size())) {
            throw std::logic_error("check: item " + std::to_string(items.size()) + " " + why);
        }
        ++counts[item.outcome];
        items.push_back(item_json(item));
    }
    return {
        {"counts",
         {{"match", counts[CheckOutcome::match]},
          {"mismatch", counts[CheckOutcome::mismatch]},
          {"missing", counts[CheckOutcome::missing]},
          {"error", counts[CheckOutcome::error]}}},
        {"stale_copies",
         {{"mail", result.stale_mail},
          {"sharepoint", result.stale_sharepoint},
          {"onedrive", result.stale_onedrive}}},
        {"items", std::move(items)},
    };
}

} // namespace rp::verification
