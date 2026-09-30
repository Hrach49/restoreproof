#include "veeam_explore.hpp"

#include <rp/redact.hpp>

#include "control_chars.hpp"
#include "json_fields.hpp"
#include "text_util.hpp"
#include "uuid.hpp"
#include "veeam_restore.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstddef>
#include <exception>
#include <string>
#include <utility>

namespace rp::veeam_explore {

namespace {

using nlohmann::json;
namespace vr = veeam_restore;

} // namespace

std::string shown(std::string_view client_ref)
{
    std::string out;
    out.reserve(client_ref.size());
    for (std::size_t i = 0; i < client_ref.size();) {
        if (const std::size_t length = control_character_length(client_ref, i); length != 0) {
            out += ' ';
            i += length;
        } else {
            out += client_ref[i];
            ++i;
        }
    }
    return out;
}

void warn(const std::shared_ptr<spdlog::logger>& logger, const std::string& line) noexcept
{
    try {
        const std::shared_ptr<spdlog::logger> to = logger ? logger : spdlog::default_logger();
        if (to) {
            to->warn("{}", redact(one_line(line)));
        }
    } catch (...) { // NOLINT(bugprone-empty-catch): logging is best effort
    }
}

Organization find_organization(VeeamClient& client, const std::string& client_ref)
{
    std::vector<Organization> matches;
    for (Organization& org : client.list_organizations()) {
        if (ascii_iequals(org.name, client_ref)) {
            matches.push_back(std::move(org));
        }
    }
    if (matches.empty()) {
        throw connector::NotFoundError("client " + shown(client_ref) + " not found in Veeam");
    }
    if (matches.size() > 1) {
        throw connector::Error("client " + shown(client_ref) + " matches " +
                               std::to_string(matches.size()) + " organisations in Veeam");
    }
    // VeeamClient would refuse it with std::invalid_argument; checked here
    // so that only this case reads as Veeam's fault.
    if (!is_uuid(matches.front().id)) {
        throw connector::Error("Veeam returned an organisation ID for client " +
                               shown(client_ref) + " that isn't a UUID");
    }
    return std::move(matches.front());
}

void check_restore_point(VeeamClient& client, const std::string& organization_id,
                         const std::string& client_ref, const connector::RestorePoint& wanted,
                         std::string_view outcome)
{
    for (const RestorePoint& point : client.list_restore_points(organization_id)) {
        if (point.id == wanted.id) {
            if (point.backup_time != wanted.backup_time) {
                throw connector::Error("veeam_m365: restore point " + one_line(wanted.id, 120) +
                                       " of client " + shown(client_ref) + " has backup time " +
                                       one_line(point.backup_time) + " in Veeam, not " +
                                       one_line(wanted.backup_time) + "; " +
                                       std::string{outcome});
            }
            return;
        }
    }
    throw connector::Error("veeam_m365: restore point " + one_line(wanted.id, 120) +
                           " isn't one of client " + shown(client_ref) +
                           "'s restore points in Veeam; " + std::string{outcome});
}

void preflight(VeeamClient& client, const std::string& account, std::string_view outcome)
{
    const json list =
        client.get_json("/v8/RestoreSessions?limit=" + std::to_string(vr::kPreflightLimit));
    const std::vector<std::string> working = vr::working_sessions(list, account);
    if (!working.empty()) {
        std::string ids;
        for (const std::string& id : working) {
            ids += (ids.empty() ? "" : ", ") + id;
        }
        throw connector::Error("veeam_m365: Veeam has restore sessions of " + one_line(account) +
                               " still Working (" + ids +
                               "); stop them first (docs/api/veeam-m365/08-sweep-sessions.ps1); " +
                               std::string{outcome});
    }
}

void ExploreSessions::set_organization(std::string id, std::string name)
{
    organization_id_ = std::move(id);
    organization_name_ = std::move(name);
}

std::string ExploreSessions::open(connector::ItemKind kind)
{
    const auto sent = c_.wall_now();
    std::string id;
    try {
        id = c_.client.open_explore_session(organization_id_, c_.backup_time,
                                            vr::session_type(kind));
    } catch (const AuthError&) {
        throw; // no sign-in: Veeam did nothing
    } catch (const VeeamError&) {
        // Veeam may have opened the session before the answer went wrong (a
        // timeout, a 5xx, a 2xx without an ID; veeam-notes §4.4 saw a refused
        // explore leave one Working): found, it is closed like the others.
        adopt_orphans(kind, sent);
        throw;
    }
    // Recorded at once, so the finally path can stop it.
    opened_.push_back(id);
    known_.insert(id);
    return id;
}

void ExploreSessions::adopt_orphans(connector::ItemKind kind,
                                    std::chrono::system_clock::time_point sent) noexcept
{
    const std::string kind_name{connector::to_string(kind)};
    try {
        // The duplicate check's filter, Working only: our account's sessions
        // of this type and organisation, new since the POST. No restore of
        // ours runs yet, so one such is this POST's. More than one can't be
        // told apart from another process's work: none is adopted.
        const std::vector<std::string> found = duplicates(kind, sent, true);
        if (found.size() == 1) {
            warn(c_.logger, "veeam_m365: the " + kind_name +
                                " explore POST failed, but Veeam lists explore session " +
                                found.front() + " made by it; it is closed with the others");
            opened_.push_back(found.front());
            known_.insert(found.front());
        } else if (found.size() > 1) {
            std::string ids;
            for (const std::string& id : found) {
                ids += " " + id;
            }
            warn(c_.logger,
                 "veeam_m365: the " + kind_name + " explore POST failed, and Veeam lists " +
                     std::to_string(found.size()) + " new Working sessions of ours (" +
                     ids.substr(1) +
                     "); none is closed, as another may not be this POST's: stop the orphan with "
                     "docs/api/veeam-m365/08-sweep-sessions.ps1");
        }
    } catch (const std::exception& e) {
        warn(c_.logger,
             "veeam_m365: couldn't look for an explore session the failed " + kind_name +
                 " explore POST may have opened (" + e.what() +
                 "); if one of ours is Working, stop it (docs/api/veeam-m365/08-sweep-sessions.ps1)");
    }
}

std::vector<std::string> ExploreSessions::duplicates(connector::ItemKind kind,
                                                     std::chrono::system_clock::time_point posted,
                                                     bool working_only)
{
    const std::string path = "/v8/RestoreSessions?startTimeFrom=" +
                             vr::format_utc_seconds(posted - vr::kDuplicateWindow) +
                             "&orderBy=CreationTime&orderAsc=false&limit=" +
                             std::to_string(vr::kDuplicateLimit);
    vr::DuplicateFilter filter;
    filter.account = c_.account;
    filter.type = std::string{vr::session_type(kind)};
    filter.known = known_;
    filter.floor =
        std::chrono::time_point_cast<std::chrono::nanoseconds>(posted - vr::kDuplicateFloor);
    filter.organization = organization_name_;
    filter.working_only = working_only;
    return vr::new_restore_sessions(c_.client.get_json(path), filter);
}

void ExploreSessions::keep_open(bool keep, std::string running)
{
    keep_open_ = keep;
    running_session_ = std::move(running);
}

std::string ExploreSessions::left_open() const
{
    if (!keep_open_) {
        return {};
    }
    std::string out = "; left open, as a restore may still be running:";
    if (!running_session_.empty()) {
        out += " restore session " + running_session_ + ",";
    }
    out += " explore session(s)";
    for (const std::string& id : opened_) {
        out += " " + id;
    }
    return out;
}

bool ExploreSessions::is_working(const std::string& id)
{
    const json session = c_.client.get_json("/v8/RestoreSessions/" + id);
    const std::string* state = string_at(session, "state");
    return state != nullptr && *state == "Working";
}

bool ExploreSessions::stop_if_working(const std::string& id) noexcept
{
    try {
        if (!is_working(id)) {
            return true;
        }
        try {
            c_.client.stop_session(id);
        } catch (const TransientError& e) {
            // 2026-09-30 (veeam-notes §4.4): a Stop timed out with the session
            // still Working, and a second Stop minutes later stopped it at
            // once. Read it again and send one more Stop only if it is still
            // Working; an auth error or a 4xx is not retried.
            if (!is_working(id)) {
                return true;
            }
            warn(c_.logger, "veeam_m365: stopping explore session " + id + " failed (" +
                                e.what() + ") and it is still Working; sending Stop once more");
            c_.client.stop_session(id);
        }
        return true;
    } catch (const std::exception& e) {
        warn(c_.logger, "veeam_m365: couldn't close explore session " + id + ": " + e.what());
    }
    return false;
}

void ExploreSessions::close() noexcept
{
    if (keep_open_) {
        warn(c_.logger, "veeam_m365: explore session(s) left open" + left_open());
        return;
    }
    for (const std::string& id : opened_) {
        stop_if_working(id);
    }
}

std::vector<std::string> ExploreSessions::close_checked()
{
    std::vector<std::string> failed;
    for (const std::string& id : opened_) {
        if (!stop_if_working(id)) {
            failed.push_back(id);
        }
    }
    opened_.clear();
    return failed;
}

} // namespace rp::veeam_explore
