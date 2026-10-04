#pragma once

// Paging through a restore target's listing, shared by the two readers of the
// targets: TargetReader (W2.2, rp/graph_targets.hpp) and the Cleaner (W3.4),
// so both keep one paging rule and one rule per target for where a nextLink
// may lead (docs/decisions.md 2026-10-02, W3.4 point 2).

#include <rp/graph_client.hpp>
#include <rp/graph_targets.hpp>
#include <rp/http_client.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp::graph {

// The resource a listing URL names, to check a nextLink against its target's
// rule: the path after Graph's v1.0 root, up to the query, percent-decoded,
// "seg('v')" and "seg(v)" as "seg/v", lower case, split at '/'.
std::vector<std::string> resource_path(std::string_view url);

// Every page of a listing that starts at `first` (a path under Graph's v1.0
// root), following @odata.nextLink while `next_rule` takes the resource_path()
// of each link, at most kMaxListPages pages. A page without a "value" array, a
// link that isn't absolute under v1.0, one already fetched or one the rule
// refuses is a GraphError naming `what`. A listing that goes past the last
// page allowed is a GraphError too, unless `past_limit` is given: then the
// pages up to the limit are returned and *past_limit is set (false otherwise;
// the Cleaner deletes what it listed, W3.4 point 2). The link past the limit
// is checked like any other but never fetched. Graph's own errors are thrown
// as GraphClient throws them.
std::vector<nlohmann::json> list_pages(GraphClient& graph, const std::string& first,
                                       const Grant& grant, const HttpHeaders& headers,
                                       const std::string& what, const NextLinkRule& next_rule,
                                       bool* past_limit = nullptr);

// Q3.2: SharePoint doesn't refuse a listing the app lacks the grant for; it
// answers 200 and leaves out what the app may not read (security trimming),
// while the container's own folder.childCount still counts every child (live,
// 2026-10-04: the RestoreTarget library's root said 1, its listing was empty).
// An empty or short listing taken at face value turns a missing permission
// into a `fail`, and a cleanup into "nothing to delete". So both readers of a
// file target read the container's count first and hold the listing to it.

// The RestoreTarget library's count: folder.childCount of
// GET /drives/{drive}/root?$select=id,folder; nullopt when the reply has
// none. Graph's errors are thrown as GraphClient throws them.
std::optional<std::uint64_t> library_child_count(GraphClient& graph, const std::string& drive);

// A folder facet's childCount, when it is a number of 0 or more.
std::optional<std::uint64_t> child_count_of(const nlohmann::json& item);

// How many entries `pages` (list_pages') list.
std::size_t listed_entries(const std::vector<nlohmann::json>& pages);

// Holds a listing of `listed` entries to its container's `child_count`, read
// before the listing: more children than entries is a PermissionError naming
// `grant` (so the run's code is graph_permission: `error`, never `fail`); no
// count is a GraphError, since the listing can't be shown to be whole. More
// entries than the count is fine: something was added in between.
void check_listing_whole(const std::optional<std::uint64_t>& child_count, std::size_t listed,
                         const Grant& grant, const std::string& what);

// Reads a file target's count again, as the read before its listing did.
using CountReader = std::function<std::optional<std::uint64_t>()>;

// How often a listing shorter than its container's count is read again, and
// the wait before each: 6 s in all before the listing is refused.
inline constexpr int kListingRechecks = 3;
inline constexpr std::chrono::milliseconds kListingRecheckWait{2000};

// list_pages for a file target, held to its container's count
// (check_listing_whole). A listing shorter than `child_count` isn't refused
// at once (PR #155 review): the count may trail a delete (the clean before
// the snapshot, a Cleaner round before the next), and an entry may go between
// the two reads. The Worker waits kListingRecheckWait on the client's sleep,
// reads the count again with `recount` and lists again, at most
// kListingRechecks times; a listing still short then was trimmed: the
// PermissionError. A missing count is the GraphError at once. A listing cut
// at kMaxListPages (`past_limit` given and set) is short by design and isn't
// held to the count.
std::vector<nlohmann::json> list_whole(GraphClient& graph, const std::string& first,
                                       const Grant& grant, const std::string& what,
                                       const NextLinkRule& next_rule,
                                       std::optional<std::uint64_t> child_count,
                                       const CountReader& recount, bool* past_limit = nullptr);

// Whether `id`, the "id" of an entry Graph listed, may go in a URL path: 1 to
// 512 ASCII letters, digits and "!-_=" (Exchange's IDs end in '=').
bool is_listed_id(std::string_view id) noexcept;

// A nextLink's path may name the same target in another form than the first
// request did (review of W2.2): Graph documents the link as opaque. These take
// the forms that still name the guarded target, and nothing that could reach
// another folder of the same drive (alice's canaries share hers). `path` is
// resource_path()'s.

// users/{the mailbox, or an object ID}/mailfolders/inbox/messages
bool is_inbox_path(const std::vector<std::string>& path, const std::string& mailbox);

// drives/{drive}/root/children, or drives/{drive}/items/{an item ID}/children
bool is_library_root_path(const std::vector<std::string>& path, const std::string& drive);

// drives/{drive}/items/{folder}/children: that folder only.
bool is_folder_path(const std::vector<std::string>& path, const std::string& drive,
                    const std::string& folder);

} // namespace rp::graph
