// W3.4: the last check GraphClient::remove makes before it sends a delete
// (src/graph_write_rule.hpp). A ListedItem is made only by the Cleaner, whose
// own rules are stricter, so remove() can't be driven into this refusal
// through it; the rule is tested here on its own instead (W3.4 review).

#include "../src/graph_write_rule.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <string>

namespace {

using rp::graph::is_sendable_item;

const std::string kMailbox = "restoretest@lab.example";
const std::string kDrive = "b!AbC-_09";
const std::string kId = "01ABCDEF-_!";
const std::string kMailId = "AAkALgAA-_=";
const std::string kEtag = "\"{3F2A},4\"";

} // namespace

// ---- failure paths -------------------------------------------------------------------------

TEST_CASE("remove()'s last check refuses parts that could change a request's shape",
          "[graph][write_rule]")
{
    struct Row {
        const char* name;
        bool mail;
        std::string container;
        std::string id;
        std::string etag;
    };
    const Row row = GENERATE_COPY(
        Row{"empty mailbox", true, "", kMailId, ""},
        Row{"a slash in the mailbox", true, "restoretest@lab/../alice", kMailId, ""},
        Row{"a '?' in the mailbox", true, "restoretest@lab?x=1", kMailId, ""},
        Row{"empty mail ID", true, kMailbox, "", ""},
        Row{"a slash in a mail ID", true, kMailbox, "AAk/move", ""},
        Row{"a '?' in a mail ID", true, kMailbox, "AAk?x", ""},
        Row{"a 513-character mail ID", true, kMailbox, std::string(513, 'A'), ""},
        Row{"empty drive", false, "", kId, kEtag},
        Row{"a slash in the drive", false, "b!x/items/y", kId, kEtag},
        Row{"a '@' in the drive", false, "b!x@y", kId, kEtag},
        Row{"empty file ID", false, kDrive, "", kEtag},
        Row{"a slash in a file ID", false, kDrive, "01A/children", kEtag},
        Row{"a '?' in a file ID", false, kDrive, "01A?x", kEtag},
        Row{"a '%' in a file ID", false, kDrive, "01A%2F", kEtag},
        Row{"a space in a file ID", false, kDrive, "01A B", kEtag},
        Row{"a 513-character file ID", false, kDrive, std::string(513, 'A'), kEtag},
        Row{"empty eTag", false, kDrive, kId, ""},
        Row{"CR LF in the eTag", false, kDrive, kId, "\"x\"\r\nX-Other: y"},
        Row{"LF in the eTag", false, kDrive, kId, "\"x\"\n"},
        Row{"a NUL in the eTag", false, kDrive, kId, std::string{"\"x\0\"", 4}});
    INFO(row.name);
    CHECK_FALSE(is_sendable_item(row.mail, row.container, row.id, row.etag));
}

// ---- happy paths ---------------------------------------------------------------------------

TEST_CASE("remove()'s last check takes Graph's and Exchange's parts", "[graph][write_rule]")
{
    CHECK(is_sendable_item(true, kMailbox, kMailId, ""));
    CHECK(is_sendable_item(true, "restore.test+x_y-z'q@lab.example", kMailId, ""));
    CHECK(is_sendable_item(true, kMailbox, std::string(512, 'A'), ""));
    CHECK(is_sendable_item(false, kDrive, kId, kEtag));
    CHECK(is_sendable_item(false, kDrive, std::string(512, '0'), "x"));
    // A mail's eTag isn't sent: it doesn't matter.
    CHECK(is_sendable_item(true, kMailbox, kMailId, "\r\n"));
}
