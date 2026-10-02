#pragma once

// Paging through a restore target's listing, shared by the two readers of the
// targets: TargetReader (W2.2, rp/graph_targets.hpp) and the Cleaner (W3.4),
// so both keep one paging rule and one rule per target for where a nextLink
// may lead (docs/decisions.md 2026-10-02, W3.4 point 2).

#include <rp/graph_client.hpp>
#include <rp/graph_targets.hpp>
#include <rp/http_client.hpp>

#include <nlohmann/json.hpp>

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
