#include "text_table.hpp"

#include "text_util.hpp"

#include <algorithm>

namespace rp {

std::string table_cell(std::string_view text)
{
    return one_line(text, text.size());
}

std::size_t display_width(std::string_view text) noexcept
{
    return static_cast<std::size_t>(std::ranges::count_if(
        text, [](char c) { return (static_cast<unsigned char>(c) & 0xC0) != 0x80; }));
}

std::string format_table(const std::vector<TableRow>& rows)
{
    std::vector<std::size_t> widths;
    for (const TableRow& row : rows) {
        widths.resize(std::max(widths.size(), row.cells.size()));
        for (std::size_t i = 0; i < row.cells.size(); ++i) {
            widths[i] = std::max(widths[i], display_width(row.cells[i]));
        }
    }
    std::string text;
    for (const TableRow& row : rows) {
        std::string line = row.prefix;
        for (std::size_t i = 0; i < row.cells.size(); ++i) {
            line += row.cells[i];
            if (i + 1 < row.cells.size()) {
                line.append(widths[i] - display_width(row.cells[i]) + 2, ' ');
            }
        }
        line.erase(line.find_last_not_of(' ') + 1);
        text += line + '\n';
    }
    return text;
}

} // namespace rp
