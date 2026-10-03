#pragma once

// The last check GraphClient's one write member makes before it sends a
// delete (W3.4, docs/decisions.md 2026-10-02 point 3): the item's parts go
// into the path and a header as they are, so anything that could change the
// path's shape or split a header is refused before anything is sent. The
// Cleaner, the only code that makes an item to delete, checks them first by
// its own stricter rules; this is the client's own line, tested on its own
// (tests/graph_write_rule_test.cpp). Only graph_client.cpp includes it.

#include <string_view>

namespace rp::graph {

// Whether a delete of these parts may be sent: a mailbox's address of ASCII
// letters, digits and "@.-_+'", or a drive ID of letters, digits and "!-_";
// an ID of 1 to 512 letters, digits and "!-_="; and for a file (`mail`
// false) an eTag that is neither empty nor holds a control character. A
// mail's eTag isn't sent and isn't looked at.
bool is_sendable_item(bool mail, std::string_view container, std::string_view id,
                      std::string_view etag) noexcept;

} // namespace rp::graph
