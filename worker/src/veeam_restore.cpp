#include "veeam_restore.hpp"

#include <rp/config.hpp>
#include <rp/redact.hpp>

#include "json_fields.hpp"
#include "text_util.hpp"
#include "uuid.hpp"

#include <algorithm>
#include <array>
#include <iterator>
#include <map>
#include <string>
#include <utility>

namespace rp::veeam_restore {

namespace {

using nlohmann::json;
using nlohmann::ordered_json;

// What Veeam says when it couldn't reach Microsoft 365 (or a target), was
// refused, throttled or timed out: W1.0's recorded failures (the first five)
// and the other ways a service call fails. Lower case; matched in Veeam's own
// words only (veeam_words). Deliberately broad: a restore that couldn't run
// must never be reported as `fail` (CLAUDE.md), so any doubt goes to `error`.
constexpr std::array<std::string_view, 27> kInfrastructureTexts = {
    "cannot connect to microsoft 365",
    "failed to open mailbox",
    "failed to access mailbox",
    "missing the required application permissions",
    "aadsts",
    "failed to connect",
    "unable to connect",
    "could not connect",
    "connection",
    "access denied",
    "access is denied",
    "unauthorized",
    "forbidden",
    "(401)",
    "(403)",
    "(429)",
    "too many requests",
    "throttl",
    "(503)",
    "service unavailable",
    "server busy",
    "timed out",
    "timeout",
    "proxy",
    "could not be resolved",
    "certificate",
    "token",
};

// What replaces a cut: a unit separator, which no marker holds, so a cut
// never joins two words into a marker.
constexpr char kCut = '\x1F';

// The string at `key`, empty when it is missing or null; ShapeError for any
// other kind.
std::string optional_text(const json& object, std::string_view key)
{
    const auto it = object.find(key);
    if (it == object.end() || it->is_null()) {
        return {};
    }
    if (!it->is_string()) {
        throw ShapeError("\"" + std::string{key} + "\" isn't a string");
    }
    return it->get<std::string>();
}

bool is_space(char c) noexcept
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

// `out` with [from, to) replaced by one cut.
void cut(std::string& out, std::size_t from, std::size_t to)
{
    out.replace(from, to - from, 1, kCut);
}

// The "results" array of a list reply.
const json& results_of(const json& list)
{
    const auto it = list.is_object() ? list.find("results") : list.end();
    if (it == list.end() || !it->is_array()) {
        throw ShapeError("no \"results\" list");
    }
    return *it;
}

bool is_lower_uuid(std::string_view id) noexcept
{
    return is_uuid(id) && std::ranges::none_of(id, [](char c) { return c >= 'A' && c <= 'Z'; });
}

std::string two_digits(unsigned value)
{
    return std::string{static_cast<char>('0' + value / 10 % 10),
                       static_cast<char>('0' + value % 10)};
}

// A server's text, fit for one line of RestoreResult::log.
std::string log_line(std::string_view text)
{
    return redact(one_line(text));
}

} // namespace

std::string_view session_type(connector::ItemKind kind) noexcept
{
    switch (kind) {
    case connector::ItemKind::sharepoint:
        return "Vesp";
    case connector::ItemKind::onedrive:
        return "Veod";
    case connector::ItemKind::mail:
        break;
    }
    return "Vex";
}

std::string bare_account(std::string_view username)
{
    const std::size_t slash = username.rfind('\\');
    return std::string{slash == std::string_view::npos ? username : username.substr(slash + 1)};
}

std::string format_utc_seconds(std::chrono::system_clock::time_point time)
{
    const auto seconds = std::chrono::floor<std::chrono::seconds>(time);
    const auto days = std::chrono::floor<std::chrono::days>(seconds);
    const std::chrono::year_month_day date{days};
    const std::chrono::hh_mm_ss clock{seconds - days};
    const int year = static_cast<int>(date.year());
    std::string out = std::to_string(year);
    out.insert(0, out.size() < 4 ? 4 - out.size() : 0, '0');
    return out + "-" + two_digits(static_cast<unsigned>(date.month())) + "-" +
           two_digits(static_cast<unsigned>(date.day())) + "T" +
           two_digits(static_cast<unsigned>(clock.hours().count())) + ":" +
           two_digits(static_cast<unsigned>(clock.minutes().count())) + ":" +
           two_digits(static_cast<unsigned>(clock.seconds().count())) + "Z";
}

std::optional<std::string> veeam_site_id(std::string_view graph_site_id)
{
    const std::optional<GraphSiteId> parsed = parse_graph_site_id(graph_site_id);
    if (!parsed) {
        return std::nullopt;
    }
    return ascii_lower(parsed->site + parsed->web);
}

std::optional<std::string> onedrive_url(std::string_view sharepoint_host, std::string_view user)
{
    const std::optional<std::string> host = onedrive_host(sharepoint_host);
    if (user.empty() || !host) {
        return std::nullopt;
    }
    std::string personal = ascii_lower(user);
    std::ranges::replace(personal, '@', '_');
    std::ranges::replace(personal, '.', '_');
    return "https://" + *host + "/personal/" + personal;
}

std::vector<std::string> path_segments(std::string_view folder_path)
{
    std::vector<std::string> out;
    std::size_t at = 0;
    while (at <= folder_path.size()) {
        const std::size_t slash = std::min(folder_path.find('/', at), folder_path.size());
        const std::string_view segment = folder_path.substr(at, slash - at);
        if (!segment.empty() && segment != ".") {
            out.emplace_back(segment);
        }
        at = slash + 1;
    }
    return out;
}

bool is_uuid_run(std::string_view id) noexcept
{
    if (id.empty() || id.size() % 36 != 0) {
        return false;
    }
    for (std::size_t at = 0; at < id.size(); at += 36) {
        if (!is_uuid(id.substr(at, 36))) {
            return false;
        }
    }
    return true;
}

std::string veeam_words(std::string_view text, const std::vector<std::string>& tenant_texts)
{
    std::string out{text};
    // 1. The tenant's texts the run knows, whole, case as they are.
    for (const std::string& name : tenant_texts) {
        if (name.empty()) {
            continue;
        }
        for (std::size_t at = out.find(name); at != std::string::npos; at = out.find(name, at + 1)) {
            cut(out, at, at + name.size());
        }
    }
    // 2. Veeam's "source: ...;" and "target: ...)" fields: a display name, a
    //    folder, a path or an address, the tenant's all.
    for (const std::string_view key : {std::string_view{"source:"}, std::string_view{"target:"}}) {
        for (std::size_t at = ascii_lower(out).find(key); at != std::string::npos;
             at = ascii_lower(out).find(key, at + 1)) {
            cut(out, at, std::min(out.find_first_of(";)", at), out.size()));
        }
    }
    // 3. Quoted parts: "..." anywhere, '...' when the quote opens a word (not
    //    an apostrophe, as in "can't").
    for (std::size_t at = 0; at < out.size(); ++at) {
        const char quote = out[at];
        const bool opens =
            quote == '"' || (quote == '\'' && (at == 0 || is_space(out[at - 1]) ||
                                               out[at - 1] == ':' || out[at - 1] == '('));
        if (!opens) {
            continue;
        }
        const std::size_t close = out.find(quote, at + 1);
        if (close == std::string::npos) {
            break;
        }
        cut(out, at, close + 1);
    }
    // 4. Words that are an address or a path: '@', '/' or '\' in them.
    for (std::size_t start = 0; start < out.size();) {
        if (is_space(out[start])) {
            ++start;
            continue;
        }
        std::size_t end = start;
        while (end < out.size() && !is_space(out[end])) {
            ++end;
        }
        if (std::string_view{out}.substr(start, end - start).find_first_of("@/\\") !=
            std::string_view::npos) {
            cut(out, start, end);
            end = start + 1;
        }
        start = end;
    }
    return out;
}

bool is_infrastructure_text(std::string_view text)
{
    const std::string lower = ascii_lower(text);
    return std::ranges::any_of(kInfrastructureTexts, [&](std::string_view marker) {
        return lower.find(marker) != std::string::npos;
    });
}

std::vector<std::string> working_sessions(const json& list, std::string_view account)
{
    std::vector<std::string> out;
    for (const json& session : results_of(list)) {
        if (!session.is_object()) {
            throw ShapeError("a session that isn't an object");
        }
        if (optional_text(session, "state") == "Working" &&
            ascii_iequals(optional_text(session, "initiatedBy"), account)) {
            out.push_back(one_line(optional_text(session, "id"), 64));
        }
    }
    return out;
}

std::vector<connector::OwnSession> own_working_sessions(const std::vector<json>& entries,
                                                        std::string_view account, UtcTime since)
{
    std::vector<std::pair<UtcTime, std::string>> found;
    for (const json& session : entries) {
        const std::string* state = string_at(session, "state");
        if (state == nullptr) {
            throw ShapeError("a session without a \"state\"");
        }
        const std::string* by = string_at(session, "initiatedBy");
        if (by == nullptr) {
            throw ShapeError("a session without an \"initiatedBy\"");
        }
        if (*state != "Working" || !ascii_iequals(*by, account)) {
            continue;
        }
        const std::string* id = string_at(session, "id");
        if (id == nullptr || !is_uuid(*id)) {
            throw ShapeError("a session ID that isn't a UUID");
        }
        const std::string* created = string_at(session, "creationTime");
        const std::optional<UtcTime> at =
            created != nullptr ? parse_veeam_time(*created) : std::nullopt;
        if (!at) {
            throw ShapeError("a session without a \"creationTime\" in Veeam's UTC form");
        }
        if (*at >= since) {
            found.emplace_back(*at, ascii_lower(*id));
        }
    }
    // Veeam was asked for them newest first; not relied on.
    std::ranges::stable_sort(found, [](const auto& a, const auto& b) { return a.first > b.first; });
    std::vector<connector::OwnSession> out;
    out.reserve(found.size());
    for (auto& [at, id] : found) {
        out.push_back({std::move(id),
                       std::chrono::time_point_cast<std::chrono::system_clock::duration>(at)});
    }
    return out;
}

std::vector<std::string> new_restore_sessions(const json& list, const DuplicateFilter& filter)
{
    std::vector<std::string> out;
    for (const json& session : results_of(list)) {
        const std::string* id = string_at(session, "id");
        const std::string* by = string_at(session, "initiatedBy");
        const std::string* type = string_at(session, "type");
        const std::string* created = string_at(session, "creationTime");
        if (id == nullptr || by == nullptr || type == nullptr || created == nullptr) {
            continue;
        }
        // Another organisation's session is never ours. Without the field it
        // is kept: for the duplicate check a missing field only adds a
        // candidate (no verdict), never hides one.
        if (!filter.organization.empty() && session.contains("organization")) {
            const std::string* organization = string_at(session, "organization");
            if (organization == nullptr || !ascii_iequals(*organization, filter.organization)) {
                continue;
            }
        }
        if (filter.working_only) {
            const std::string* state = string_at(session, "state");
            if (state == nullptr || *state != "Working") {
                continue;
            }
        }
        const std::optional<UtcTime> at = parse_veeam_time(*created);
        if (is_lower_uuid(*id) && !filter.known.contains(*id) && ascii_iequals(*by, filter.account) &&
            *type == filter.type && at && *at >= filter.floor) {
            out.push_back(*id);
        }
    }
    return out;
}

std::vector<std::vector<std::size_t>> split_calls(const std::vector<std::string>& containers,
                                                  const std::vector<std::string>& names)
{
    // Per container, in the order containers first appear: its calls, and
    // how often each name has come up in it so far.
    struct Container {
        std::string id;
        std::vector<std::vector<std::size_t>> calls;
        std::map<std::string, std::size_t> seen;
    };
    std::vector<Container> order;
    for (std::size_t i = 0; i < containers.size(); ++i) {
        auto it = std::ranges::find(order, containers[i], &Container::id);
        if (it == order.end()) {
            order.push_back({containers[i], {}, {}});
            it = std::prev(order.end());
        }
        const std::size_t call = it->seen[names[i]]++;
        if (call == it->calls.size()) {
            it->calls.emplace_back();
        }
        it->calls[call].push_back(i);
    }
    std::vector<std::vector<std::size_t>> out;
    for (Container& container : order) {
        for (std::vector<std::size_t>& call : container.calls) {
            out.push_back(std::move(call));
        }
    }
    return out;
}

ordered_json mail_body(const std::vector<std::string>& item_ids, const std::string& target_mailbox,
                       const OrganizationFacts& org)
{
    ordered_json items = ordered_json::array();
    for (const std::string& id : item_ids) {
        items.push_back({{"id", id}});
    }
    ordered_json body;
    body["mailbox"] = target_mailbox;
    body["folder"] = "Inbox";
    body["items"] = std::move(items);
    body["changedItems"] = true;
    body["deletedItems"] = true;
    body["markRestoredAsUnread"] = false;
    body["excludeDrafts"] = false;
    body["excludeDeletedItems"] = false;
    body["excludeInPlaceHoldItems"] = true;
    body["excludeLitigationHoldItems"] = true;
    body["officeRegion"] = org.office_region;
    body["officeOrganizationName"] = org.organization_name;
    body["applicationId"] = org.application_id;
    body["applicationCertificate"] = "";
    body["applicationCertificatePassword"] = "";
    body["impersonationAccountName"] = target_mailbox;
    return body;
}

ordered_json sharepoint_body(std::vector<ordered_json> documents, const std::string& site_url,
                             const std::string& list, const OrganizationFacts& org)
{
    ordered_json body;
    body["documents"] = std::move(documents);
    body["siteURL"] = site_url;
    body["list"] = list;
    body["sendSharedLinksNotification"] = false;
    body["documentVersion"] = "Last";
    body["documentLastVersionAction"] = "Merge";
    body["officeRegion"] = org.office_region;
    body["organizationName"] = org.organization_name;
    body["applicationId"] = org.application_id;
    body["applicationCertificate"] = "";
    body["applicationCertificatePassword"] = "";
    return body;
}

ordered_json onedrive_body(std::vector<ordered_json> documents, const ordered_json& onedrive,
                           const std::string& folder, const OrganizationFacts& org)
{
    ordered_json body;
    body["documents"] = std::move(documents);
    body["onedrive"] = onedrive;
    body["folder"] = folder;
    body["changedItems"] = true;
    body["deletedItems"] = true;
    body["documentVersion"] = "Last";
    body["documentLastVersionAction"] = "Merge";
    body["officeRegion"] = org.office_region;
    body["organizationName"] = org.organization_name;
    body["applicationId"] = org.application_id;
    body["applicationCertificate"] = "";
    body["applicationCertificatePassword"] = "";
    return body;
}

ordered_json body_document(ordered_json reread)
{
    reread.erase("_links");
    reread.erase("_actions");
    return reread;
}

SessionState read_session(const json& session)
{
    if (!session.is_object()) {
        throw ShapeError("a session that isn't an object");
    }
    SessionState out;
    out.state = optional_text(session, "state");
    if (out.state.empty()) {
        throw ShapeError("a session without a \"state\"");
    }
    out.result = optional_text(session, "result");
    out.details = optional_text(session, "details");
    out.creation_time = optional_text(session, "creationTime");
    out.end_time = optional_text(session, "endTime");
    return out;
}

Statistics read_statistics(const json& statistics)
{
    if (!statistics.is_object()) {
        throw ShapeError("statistics that aren't an object");
    }
    Statistics out;
    const auto restored = statistics.find("restoredItemsCount");
    if (restored == statistics.end() || !restored->is_number_integer() ||
        restored->get<std::int64_t>() < 0) {
        throw ShapeError("no whole \"restoredItemsCount\"");
    }
    out.restored = restored->get<std::int64_t>();
    const auto items = statistics.find("items");
    if (items == statistics.end() || !items->is_array()) {
        throw ShapeError("no \"items\" list");
    }
    for (const json& item : *items) {
        if (!item.is_object()) {
            throw ShapeError("a statistics item that isn't an object");
        }
        out.items.push_back({optional_text(item, "id"), optional_text(item, "status")});
    }
    if (const auto errors = statistics.find("errors");
        errors != statistics.end() && !errors->is_null()) {
        if (!errors->is_array()) {
            throw ShapeError("\"errors\" isn't a list");
        }
        for (const json& error : *errors) {
            if (!error.is_string()) {
                throw ShapeError("an error that isn't a string");
            }
            out.errors.push_back(error.get<std::string>());
        }
    }
    return out;
}

std::vector<Event> read_events(const json& page)
{
    std::vector<Event> out;
    for (const json& event : results_of(page)) {
        if (!event.is_object()) {
            throw ShapeError("an event that isn't an object");
        }
        out.push_back({optional_text(event, "type"), optional_text(event, "status"),
                       optional_text(event, "itemName"), optional_text(event, "title"),
                       optional_text(event, "message")});
    }
    return out;
}

SessionVerdict judge(connector::ItemKind kind, const std::string& session_id,
                     const SessionState& session, const Statistics& statistics,
                     const std::vector<Event>& events, const std::vector<SentItem>& sent,
                     const std::vector<std::string>& tenant_texts)
{
    SessionVerdict out;
    // The session's own failure: what reads as infrastructure, else its first
    // failing session-level event, else its first statistics error.
    std::string infrastructure;
    std::string session_failure;
    // Only Veeam's own words count: every item's name (a sampled mail's
    // subject, a file's name), the run's other tenant texts, and the
    // addresses, paths and quoted parts in a message are cut out first
    // (veeam_words), and an item Veeam restored says nothing about
    // infrastructure.
    std::vector<std::string> cuts = tenant_texts;
    for (const SentItem& item : sent) {
        cuts.push_back(item.name);
    }
    for (const Event& event : events) {
        cuts.push_back(event.item_name);
    }
    const auto reads_as_infrastructure = [&](const std::string& text) {
        return is_infrastructure_text(veeam_words(text, cuts));
    };
    const auto note = [&](const std::string& text) {
        if (infrastructure.empty() && reads_as_infrastructure(text)) {
            infrastructure = text;
        }
    };
    bool any_item_reported = false;
    for (const Event& event : events) {
        if (event.type != "Restore") {
            note(event.title);
            note(event.message);
            if (session_failure.empty() && event.status != "Success") {
                session_failure = !event.message.empty() ? event.message : event.title;
            }
            continue;
        }
        any_item_reported = true;
        if (event.status != "Success") {
            note(event.title);
            note(event.message);
        }
    }
    for (const std::string& error : statistics.errors) {
        note(error);
    }
    if (session_failure.empty() && !statistics.errors.empty()) {
        session_failure = statistics.errors.front();
    }
    if (!infrastructure.empty()) {
        out.infrastructure = true;
        out.infrastructure_text = log_line(infrastructure);
        session_failure = infrastructure;
    } else if (statistics.restored == 0 && !any_item_reported) {
        // Nothing restored, and Veeam said nothing about any item: the restore
        // never reached them, so nothing is known about the backup. Whatever
        // the reason, it is the test that couldn't run, never `fail`.
        out.infrastructure = true;
        const std::string reason = !session_failure.empty()   ? session_failure
                                   : !session.details.empty() ? session.details
                                                              : "result " + session.result;
        out.infrastructure_text = log_line("Veeam reported on none of the items: " + reason);
    }

    bool all_restored = true;
    for (const SentItem& item : sent) {
        connector::ItemRestoreResult result;
        result.kind = kind;
        result.name = item.name;
        result.session_id = session_id;
        const auto named = [&](const Event& e) {
            return e.type == "Restore" && e.item_name == item.name;
        };
        const auto success = std::ranges::find_if(
            events, [&](const Event& e) { return named(e) && e.status == "Success"; });
        const auto other = std::ranges::find_if(
            events, [&](const Event& e) { return named(e) && e.status != "Success"; });
        bool listed = kind == connector::ItemKind::mail;
        if (!listed) {
            const std::string_view key =
                kind == connector::ItemKind::sharepoint && item.id.size() >= 36
                    ? std::string_view{item.id}.substr(item.id.size() - 36)
                    : std::string_view{item.id};
            listed = std::ranges::any_of(statistics.items, [&](const StatisticsItem& s) {
                return s.status == "Success" && ascii_iequals(s.id, key);
            });
        }
        std::string message;
        if (success != events.end() && listed) {
            result.outcome = connector::ItemOutcome::restored;
            message = success->message;
        } else if (other != events.end()) {
            result.outcome = connector::ItemOutcome::failed;
            message = other->message;
        } else {
            message = session_failure;
        }
        result.message = log_line(message);
        result.infrastructure = result.outcome != connector::ItemOutcome::restored &&
                                reads_as_infrastructure(message);
        all_restored = all_restored && result.outcome == connector::ItemOutcome::restored;
        out.items.push_back(std::move(result));
    }
    out.succeeded = session.result == "Success" &&
                    statistics.restored == static_cast<std::int64_t>(sent.size()) && all_restored;

    std::string header = "session " + session_id + " (" +
                         std::string{connector::to_string(kind)} + "): " + session.result;
    if (!session.details.empty()) {
        header += ", " + session.details;
    }
    out.log_lines.push_back(log_line(header));
    for (const Event& event : events) {
        if (event.type == "Restore" || event.status != "Success") {
            out.log_lines.push_back(log_line(
                event.status + " " + (!event.item_name.empty() ? event.item_name : event.title) +
                ": " + event.message));
        }
    }
    return out;
}

connector::RestoreStatus overall_status(std::size_t sessions, std::int64_t restored,
                                        bool all_succeeded, std::size_t not_in_point) noexcept
{
    if (sessions == 0 && not_in_point == 0) {
        return connector::RestoreStatus::not_run;
    }
    if (restored == 0) {
        return connector::RestoreStatus::failed;
    }
    return all_succeeded && not_in_point == 0 ? connector::RestoreStatus::succeeded
                                              : connector::RestoreStatus::partial;
}

} // namespace rp::veeam_restore
