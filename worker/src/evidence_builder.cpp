#include <rp/evidence_builder.hpp>

#include <rp/sha256.hpp>

#include "atomic_file.hpp"
#include "path_utf8.hpp"
#include "target_guard_refuse.hpp"
#include "text_util.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <system_error>
#include <utility>

namespace rp {

namespace {

using nlohmann::json;

constexpr std::string_view kPngSignature = "\x89PNG\r\n\x1a\n";

constexpr std::string_view kCsvHeader =
    "index,type,source,canary_id,name,expected_kind,sha256_rule,expected_sha256,found_sha256,"
    "restore_outcome,found,outcome,mismatches,verdict,code,ms\n";

// The text cells between `index` and `ms`.
constexpr std::size_t kTextCells = 14;
constexpr std::size_t kNameCell = 3;

bool holds_secret(std::string_view text, const std::vector<std::string>& secrets)
{
    return std::ranges::any_of(secrets, [&](const std::string& secret) {
        return !secret.empty() && text.find(secret) != std::string_view::npos;
    });
}

// A text cell: in double quotes, a '"' doubled, each control character a
// space, so a row is one line whatever a name holds.
std::string text_cell(std::string_view text)
{
    std::string out = "\"";
    for (const char c : without_controls(text)) {
        if (c == '"') {
            out += '"';
        }
        out += c;
    }
    out += '"';
    return out;
}

// A tenant's text as a cell a spreadsheet won't run: a leading "'" before
// '=', '+', '-' or '@'.
std::string not_a_formula(std::string_view text)
{
    const bool formula = !text.empty() && std::string_view{"=+-@"}.find(text.front()) !=
                                              std::string_view::npos;
    return (formula ? "'" : "") + std::string{text};
}

// The item's verdict and its code: "-" unless the item verdicts decided the
// run (rows 5 to 8 of the status table), as `rpworker test`'s VERDICT.
std::pair<std::string, std::string> verdict_cells(const verification::RunVerdict* verdict,
                                                  std::size_t index)
{
    const bool decided = verdict && verdict->items > 0 &&
                         verdict->verified() + verdict->failed.size() +
                                 verdict->unchecked.size() == verdict->items;
    if (!decided) {
        return {"-", ""};
    }
    if (std::ranges::find(verdict->failed, index) != verdict->failed.end()) {
        return {"failed", ""};
    }
    for (const verification::UncheckedItem& item : verdict->unchecked) {
        if (item.index == index) {
            return {"unchecked", item.error_code};
        }
    }
    return {"verified", ""};
}

std::string row(std::size_t index, const std::vector<std::string>& cells, std::string_view ms)
{
    std::string out = std::to_string(index);
    for (const std::string& cell : cells) {
        out += ',' + text_cell(cell);
    }
    out += ',';
    out += ms;
    out += '\n';
    return out;
}

// The file's bytes, or nullopt when it can't be read.
std::optional<std::string> read_file(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    std::string bytes{std::istreambuf_iterator<char>(file), {}};
    if (file.bad()) {
        return std::nullopt;
    }
    return bytes;
}

Attachment attachment_of(std::string_view name, std::string_view bytes)
{
    return {std::string{name}, sha256_hex(bytes), bytes.size()};
}

} // namespace

std::string_view to_string(ScreenshotReason reason) noexcept
{
    switch (reason) {
    case ScreenshotReason::disabled:
        return "disabled";
    case ScreenshotReason::no_page:
        return "no_page";
    case ScreenshotReason::no_browser:
        return "no_browser";
    case ScreenshotReason::login_required:
        return "login_required";
    case ScreenshotReason::timeout:
        return "timeout";
    case ScreenshotReason::failed:
        return "failed";
    }
    return "unknown";
}

const std::vector<std::string>& screenshot_reasons()
{
    static const std::vector<std::string> reasons = [] {
        std::vector<std::string> out;
        for (const ScreenshotReason reason :
             {ScreenshotReason::disabled, ScreenshotReason::no_page, ScreenshotReason::no_browser,
              ScreenshotReason::login_required, ScreenshotReason::timeout,
              ScreenshotReason::failed}) {
            out.emplace_back(to_string(reason));
        }
        return out;
    }();
    return reasons;
}

const std::vector<std::string>& attachment_names()
{
    static const std::vector<std::string> names = {std::string{kItemsCsvName},
                                                   std::string{kScreenshotName},
                                                   std::string{kSessionLogName}};
    return names;
}

std::optional<ScreenshotReason> no_screenshot_page(const ScreenshotRequest&) noexcept
{
    return ScreenshotReason::no_page;
}

json to_json(const std::vector<Attachment>& attachments)
{
    json out = json::array();
    for (const Attachment& attachment : attachments) {
        out.push_back({{"name", attachment.name},
                       {"sha256", attachment.sha256},
                       {"size_bytes", attachment.size_bytes}});
    }
    return out;
}

json to_json(const Screenshot& screenshot)
{
    if (screenshot.captured) {
        return {{"state", "captured"}};
    }
    return {{"state", "unavailable"}, {"reason", to_string(screenshot.reason)}};
}

EvidenceText EvidenceBuilder::items_csv(const EvidenceFacts& facts,
                                        const std::vector<std::string>& secrets)
{
    EvidenceText out;
    out.text = kCsvHeader;
    if (!facts.expected) {
        return out;
    }
    for (const verification::ExpectedItem& want : facts.expected->items) {
        const verification::ItemCheck* check =
            facts.check && want.index < facts.check->items.size()
                ? &facts.check->items[want.index]
                : nullptr;
        const connector::ItemRestoreResult* restored =
            facts.restore && want.index < facts.restore->items.size()
                ? &facts.restore->items[want.index]
                : nullptr;
        const auto [verdict, code] = verdict_cells(facts.verdict, want.index);
        const std::string name = want.mail ? want.mail->subject : want.file ? want.file->name : "";
        const std::vector<std::string> cells = {
            std::string{connector::to_string(want.kind)},
            std::string{verification::to_string(want.source)},
            want.canary_id,
            not_a_formula(name),
            std::string{verification::to_string(want.expected_kind)},
            want.sha256_rule,
            want.sha256,
            check ? check->found_sha256 : "",
            restored ? std::string{connector::to_string(restored->outcome)} : "",
            check ? (check->found ? "yes" : "no") : "",
            check ? std::string{verification::to_string(check->outcome)} : "",
            check ? joined(check->mismatches, ",") : "",
            verdict,
            code};
        // As given and as written: a control character becomes a space in
        // the file, which could spell a secret the raw cell doesn't.
        const bool secret = std::ranges::any_of(cells, [&](const std::string& cell) {
            return holds_secret(cell, secrets) || holds_secret(without_controls(cell), secrets);
        });
        if (secret) {
            std::vector<std::string> withheld(kTextCells);
            withheld[kNameCell] = kWithheld;
            out.text += row(want.index, withheld, "");
            ++out.withheld;
        } else {
            out.text += row(want.index, cells,
                            check && check->found ? std::to_string(check->ms) : "");
        }
    }
    return out;
}

EvidenceText EvidenceBuilder::session_log(const connector::RestoreResult* restore,
                                          const std::vector<std::string>& secrets)
{
    EvidenceText out;
    if (!restore) {
        return out;
    }
    std::string_view rest = restore->log;
    while (!rest.empty()) {
        const std::size_t end = rest.find('\n');
        const std::string_view line = rest.substr(0, end);
        if (holds_secret(line, secrets)) {
            out.text += kWithheld;
            ++out.withheld;
        } else {
            out.text += line;
        }
        out.text += '\n';
        rest = end == std::string_view::npos ? std::string_view{} : rest.substr(end + 1);
    }
    return out;
}

bool EvidenceBuilder::can_name_folder(std::string_view run_id) noexcept
{
    try {
        const std::optional<std::filesystem::path> name = path_from_utf8(run_id);
        return name && is_plain_file_name(name->native());
    } catch (...) {
        return false;
    }
}

RunFolderCheck EvidenceBuilder::make_run_folder(const std::filesystem::path& root,
                                                std::string_view run_id,
                                                std::filesystem::path& folder) noexcept
{
    try {
        if (!can_name_folder(run_id)) {
            return RunFolderCheck::not_a_folder_name;
        }
        folder = root / *path_from_utf8(run_id);
        std::error_code ec;
        std::filesystem::create_directories(root, ec);
        // One call makes it or finds something there: no look first, so a
        // folder another run made in between is never taken for this run's.
        if (std::filesystem::create_directory(folder, ec) && !ec) {
            // The writer's own first step for the longest name the folder
            // will hold, now: a path too long for it, or a folder that can't
            // be written into, is found before the restore, not after it.
            if (check_new_file(folder / *path_from_utf8(kSessionLogName)) != NewFileCheck::ok) {
                std::filesystem::remove(folder, ec);
                return RunFolderCheck::cannot_make;
            }
            return RunFolderCheck::ok;
        }
        const std::filesystem::file_status status = std::filesystem::symlink_status(folder, ec);
        return std::filesystem::exists(status) ? RunFolderCheck::exists
                                               : RunFolderCheck::cannot_make;
    } catch (...) {
        return RunFolderCheck::cannot_make;
    }
}

EvidenceBuilder::EvidenceBuilder(std::filesystem::path folder, EvidenceOptions options)
    : folder_(std::move(folder)), options_(std::move(options))
{
}

bool EvidenceBuilder::write(std::string_view name, std::string_view content) noexcept
{
    try {
        const std::filesystem::path path = folder_ / *path_from_utf8(name);
        return options_.write_file ? options_.write_file(path, content)
                                   : write_file_atomically(path, content);
    } catch (...) {
        return false;
    }
}

Screenshot EvidenceBuilder::capture(const connector::RestoreResult* restore,
                                    std::vector<Attachment>& attachments) noexcept
{
    if (!options_.screenshots_enabled) {
        return {false, ScreenshotReason::disabled};
    }
    std::error_code ec;
    std::filesystem::path png;
    try {
        png = folder_ / *path_from_utf8(kScreenshotName);
        const ScreenshotRequest request{
            png, restore ? restore->session_ids : std::vector<std::string>{}};
        // Whatever isn't a PNG of the allowed size is no attachment and
        // doesn't stay in the folder.
        const auto unavailable = [&](ScreenshotReason reason) {
            std::filesystem::remove_all(png, ec);
            return Screenshot{false, reason};
        };
        std::optional<ScreenshotReason> reason;
        try {
            reason = options_.capture ? options_.capture(request) : no_screenshot_page(request);
        } catch (...) {
            return unavailable(ScreenshotReason::failed);
        }
        if (reason) {
            // `disabled` is the builder's own word, and a value outside the
            // enum is none the result knows.
            const bool known = *reason != ScreenshotReason::disabled &&
                               to_string(*reason) != "unknown";
            return unavailable(known ? *reason : ScreenshotReason::failed);
        }
        const std::uintmax_t size = std::filesystem::file_size(png, ec);
        if (ec || size > kMaxScreenshotBytes) {
            return unavailable(ScreenshotReason::failed);
        }
        const std::optional<std::string> bytes = read_file(png);
        if (!bytes || !bytes->starts_with(kPngSignature)) {
            return unavailable(ScreenshotReason::failed);
        }
        attachments.push_back(attachment_of(kScreenshotName, *bytes));
        return {true, ScreenshotReason::failed};
    } catch (...) {
        std::filesystem::remove_all(png, ec);
        return {false, ScreenshotReason::failed};
    }
}

EvidenceBuilder::Written EvidenceBuilder::write_attachments(const EvidenceFacts& facts,
                                                            bool with_screenshot) noexcept
{
    Written out;
    try {
        const EvidenceText csv = items_csv(facts, options_.secrets);
        const EvidenceText log = session_log(facts.restore, options_.secrets);
        if (const std::size_t withheld = csv.withheld + log.withheld; withheld != 0) {
            log_security(options_.logger, "evidence: " + std::to_string(withheld) +
                                              " line(s) held a secret value and were withheld");
        }
        std::vector<Attachment> attachments;
        const auto text_file = [&](std::string_view name, const std::string& text) {
            if (write(name, text)) {
                attachments.push_back(attachment_of(name, text));
            } else {
                out.errors.push_back({std::string{name}, EvidenceFailure::not_written});
            }
        };
        text_file(kItemsCsvName, csv.text);
        text_file(kSessionLogName, log.text);
        // No screenshot beside a folder that is short of a text file: there
        // will be no result to list it.
        if (out.errors.empty()) {
            const Screenshot screenshot =
                with_screenshot ? capture(facts.restore, attachments)
                                : Screenshot{false, ScreenshotReason::failed};
            std::ranges::sort(attachments, {}, &Attachment::name);
            out.evidence = Evidence{std::move(attachments), screenshot};
        }
    } catch (...) {
        out.evidence.reset();
        out.errors.push_back({std::string{kItemsCsvName}, EvidenceFailure::not_written});
    }
    return out;
}

std::optional<EvidenceError> EvidenceBuilder::write_result(const Evidence& evidence,
                                                           std::string_view canonical) noexcept
{
    try {
        for (const Attachment& attachment : evidence.attachments) {
            const std::optional<std::filesystem::path> name = path_from_utf8(attachment.name);
            const std::optional<std::string> bytes =
                name ? read_file(folder_ / *name) : std::nullopt;
            if (!bytes || bytes->size() != attachment.size_bytes ||
                sha256_hex(*bytes) != attachment.sha256) {
                return EvidenceError{attachment.name, EvidenceFailure::changed};
            }
        }
        if (!write(kResultFileName, canonical)) {
            return EvidenceError{std::string{kResultFileName}, EvidenceFailure::not_written};
        }
        return std::nullopt;
    } catch (...) {
        return EvidenceError{std::string{kResultFileName}, EvidenceFailure::not_written};
    }
}

} // namespace rp
