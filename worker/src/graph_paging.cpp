#include "graph_paging.hpp"

#include <rp/config.hpp>
#include <rp/graph_errors.hpp>

#include "text_util.hpp"
#include "uuid.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <optional>
#include <set>
#include <utility>

namespace rp::graph {

using nlohmann::json;

std::vector<std::string> resource_path(std::string_view url)
{
    if (url.starts_with(kGraphBaseUrl)) {
        url.remove_prefix(kGraphBaseUrl.size());
    }
    const std::string path = percent_decode(url.substr(0, url.find('?')));
    std::string out;
    std::size_t start = 0;
    for (;;) {
        const std::size_t end = path.find('/', start);
        std::string_view segment =
            std::string_view{path}.substr(start, end == std::string::npos ? end : end - start);
        const std::size_t open = segment.find('(');
        if (open != std::string_view::npos && segment.ends_with(')')) {
            std::string_view value = segment.substr(open + 1, segment.size() - open - 2);
            if (value.size() >= 2 && value.front() == '\'' && value.back() == '\'') {
                value = value.substr(1, value.size() - 2);
            }
            out += std::string{segment.substr(0, open)} + "/" + std::string{value};
        } else {
            out += segment;
        }
        if (end == std::string::npos) {
            break;
        }
        out += '/';
        start = end + 1;
    }
    // The path after the root starts with '/': no empty first segment.
    const std::string folded = ascii_lower(std::string_view{out}.substr(1));
    std::vector<std::string> segments;
    for (std::size_t at = 0;;) {
        const std::size_t slash = folded.find('/', at);
        segments.push_back(folded.substr(at, slash == std::string::npos ? slash : slash - at));
        if (slash == std::string::npos) {
            return segments;
        }
        at = slash + 1;
    }
}

std::vector<json> list_pages(GraphClient& graph, const std::string& first, const Grant& grant,
                             const HttpHeaders& headers, const std::string& what,
                             const NextLinkRule& next_rule, bool* past_limit)
{
    if (past_limit != nullptr) {
        *past_limit = false;
    }
    const std::string first_url = std::string{kGraphBaseUrl} + first;
    const std::string prefix = std::string{kGraphBaseUrl} + "/";
    std::set<std::string> fetched{first_url};
    std::vector<json> pages;
    std::string url = first_url;
    for (;;) {
        json page = graph.get_json(url, grant, headers);
        const auto value = page.find("value");
        if (value == page.end() || !value->is_array()) {
            throw GraphError("Graph's reply listing " + what + " has no \"value\" array");
        }
        const auto link = page.find("@odata.nextLink");
        std::optional<json> next_link;
        if (link != page.end()) {
            next_link = *link;
        }
        pages.push_back(std::move(page));
        if (!next_link) {
            return pages;
        }
        const std::string next = next_link->is_string() ? next_link->get<std::string>() : "";
        // Graph sends absolute links. Anything else is refused here, a relative one
        // too: GraphClient would put its v1.0 root in front of it and send it.
        if (!next.starts_with(prefix) || fetched.contains(next) || !next_rule(resource_path(next))) {
            throw GraphError("Graph's reply listing " + what + " has a bad @odata.nextLink");
        }
        if (pages.size() >= static_cast<std::size_t>(kMaxListPages)) {
            if (past_limit != nullptr) {
                *past_limit = true;
                return pages;
            }
            throw GraphError("listing " + what + " went past " + std::to_string(kMaxListPages) +
                             " pages; the Worker stops there");
        }
        fetched.insert(next);
        url = next;
    }
}

bool is_listed_id(std::string_view id) noexcept
{
    constexpr std::string_view extra = "!-_=";
    return !id.empty() && id.size() <= 512 && std::all_of(id.begin(), id.end(), [extra](char c) {
        const auto byte = static_cast<unsigned char>(c);
        return byte < 0x80 && (std::isalnum(byte) || extra.find(c) != std::string_view::npos);
    });
}

bool is_inbox_path(const std::vector<std::string>& path, const std::string& mailbox)
{
    return path.size() == 5 && path[0] == "users" &&
           (path[1] == ascii_lower(mailbox) || is_uuid(path[1])) && path[2] == "mailfolders" &&
           path[3] == "inbox" && path[4] == "messages";
}

bool is_library_root_path(const std::vector<std::string>& path, const std::string& drive)
{
    const bool drive_ok = path.size() >= 4 && path[0] == "drives" && path[1] == ascii_lower(drive);
    return drive_ok && ((path.size() == 4 && path[2] == "root" && path[3] == "children") ||
                        (path.size() == 5 && path[2] == "items" && is_graph_item_id(path[3]) &&
                         path[4] == "children"));
}

bool is_folder_path(const std::vector<std::string>& path, const std::string& drive,
                    const std::string& folder)
{
    return path.size() == 5 && path[0] == "drives" && path[1] == ascii_lower(drive) &&
           path[2] == "items" && path[3] == ascii_lower(folder) && path[4] == "children";
}

} // namespace rp::graph
