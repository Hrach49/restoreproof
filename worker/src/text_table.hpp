#pragma once

// The plain-text tables the CLI's listings print (`veeam list`, `graph list`):
// UTF-8, columns left-aligned and padded by character.

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

// Text from a server as a table cell: each control character
// (control_chars.hpp), which could forge, hide or reorder a line, becomes a
// space. Never cut.
std::string table_cell(std::string_view text);

// The width of UTF-8 text in code points: every byte that isn't a
// continuation byte starts one.
std::size_t display_width(std::string_view text) noexcept;

struct TableRow {
    // Printed before the first cell, outside the columns ("* ", "  ").
    std::string prefix;
    // A row with fewer cells than another has empty ones after its last.
    std::vector<std::string> cells;
};

// One line per row: its prefix, then its cells, each column padded to its
// widest cell and two spaces apart. No line ends in a space. The cells are put
// in as they are: pass server text through table_cell() first.
std::string format_table(const std::vector<TableRow>& rows);

} // namespace rp
