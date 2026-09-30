#pragma once

// Reading what an explore session lists (W2.5, W2.6): Veeam's entries without
// trusting their shape, and finding exactly one. Shared by restore_sample,
// which finds a sample's items, and list_candidates, which lists the random
// half's candidates (docs/api/veeam-restore-flow.md §4). Moved out of
// veeam_m365_connector.cpp without a change in behaviour.

#include <rp/connector.hpp>

#include "text_util.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace rp::veeam_browse {

// A name, subject or selector value as a message shows it: one line, short.
std::string shown_text(std::string_view text);

// The string at `key` of a Veeam object; nullptr when it is missing or null,
// veeam_restore::ShapeError for another kind (or an entry that isn't an
// object).
const std::string* text_at(const nlohmann::json& object, std::string_view key);

// The bool at `key` of a Veeam object; missing or null is false,
// veeam_restore::ShapeError for another kind (or an entry that isn't an
// object).
bool bool_at(const nlohmann::json& object, std::string_view key);

// An entry's "id" (VeeamClient::get_all made sure there is one).
const std::string& id_of(const nlohmann::json& entry);

// A document entry named `name` (exactly) that isn't a folder: "isFolder" is
// there and false. An "isFolder" that is neither a bool nor null is
// veeam_restore::ShapeError.
bool is_file_named(const nlohmann::json& entry, const std::string& name);

// The one entry of `list` that `match` picks; none is
// connector::NotFoundError, several connector::Error, both naming `item` and
// what was looked for.
template <class Match>
const nlohmann::json& exactly_one(const std::vector<nlohmann::json>& list, const std::string& item,
                                  const std::string& looked_for, Match match)
{
    std::vector<const nlohmann::json*> found;
    for (const nlohmann::json& entry : list) {
        if (match(entry)) {
            found.push_back(&entry);
        }
    }
    if (found.empty()) {
        throw connector::NotFoundError("veeam_m365: " + item + ": " + looked_for +
                                       " not found in the restore point");
    }
    if (found.size() > 1) {
        throw connector::Error("veeam_m365: " + item + ": " + looked_for + " matches " +
                               std::to_string(found.size()) + " entries in the restore point");
    }
    return *found.front();
}

} // namespace rp::veeam_browse
