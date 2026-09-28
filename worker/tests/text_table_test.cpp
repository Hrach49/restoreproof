// The plain-text tables of `veeam list` and `graph list` (src/text_table.hpp).

#include "../src/text_table.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

TEST_CASE("table_cell replaces control characters with spaces and never cuts", "[text_table]")
{
    CHECK(rp::table_cell("") == "");
    CHECK(rp::table_cell("plain") == "plain");
    // CR, LF, ESC, NEL, a bidi override and the line separator.
    CHECK(rp::table_cell("a\rb\nc\x1b[2Jd\xC2\x85" "e\xE2\x80\xAE" "f\xE2\x80\xA8g") ==
          "a b c [2Jd e f g");
    const std::string long_text(2000, 'x');
    CHECK(rp::table_cell(long_text) == long_text);
}

TEST_CASE("display_width counts code points, not bytes", "[text_table]")
{
    CHECK(rp::display_width("") == 0);
    CHECK(rp::display_width("abc") == 3);
    CHECK(rp::display_width("Z\xC3\xBCrich") == 6);  // Zürich
    CHECK(rp::display_width("\xE2\x82\xAC" "1") == 2); // €1
}

TEST_CASE("format_table pads each column to its widest cell, two spaces apart", "[text_table]")
{
    const std::vector<rp::TableRow> rows{
        {"  ", {"NAME", "SIZE", "ID"}},
        {"* ", {"Z\xC3\xBCrich.txt", "7", "01A"}},
        {"  ", {"a", "12345", "01BCD"}},
    };

    CHECK(rp::format_table(rows) == "  NAME        SIZE   ID\n"
                                    "* Z\xC3\xBCrich.txt  7      01A\n"
                                    "  a           12345  01BCD\n");
}

TEST_CASE("format_table gives a short row empty cells and ends no line in a space", "[text_table]")
{
    const std::vector<rp::TableRow> rows{
        {"  ", {"A", "B", "C"}},
        {"  ", {"long value", "(none)"}},
        {"  ", {"x", "", "trailing  "}},
    };

    CHECK(rp::format_table(rows) == "  A           B       C\n"
                                    "  long value  (none)\n"
                                    "  x                   trailing\n");
}

TEST_CASE("format_table of no rows is empty", "[text_table]")
{
    CHECK(rp::format_table({}).empty());
}
