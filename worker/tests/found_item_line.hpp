#pragma once

// The line graph_targets_live_test prints per item, for the person running it
// to compare with the tenant: type, id, name (files) or subject (mail), size,
// hash. The name and subject are Graph's text, so their control characters
// (control_chars.hpp: CR, LF, bidi overrides) are replaced as for any log
// line, and a restored item can't forge or reorder the output (review of W2.2).

#include "../src/text_util.hpp"

#include <rp/graph_targets.hpp>

#include <string>

namespace rp::test {

inline std::string found_item_line(const rp::graph::FoundItem& item)
{
    const std::string text = item.name ? *item.name : item.subject.value_or("");
    return std::string{rp::graph::to_string(item.type)} + "  " + rp::one_line(item.id) + "  " +
           rp::one_line(text) + "  " +
           (item.size_bytes ? std::to_string(*item.size_bytes) : std::string{"-"}) + "  " +
           item.sha256 + " (" + item.sha256_rule + ")";
}

} // namespace rp::test
