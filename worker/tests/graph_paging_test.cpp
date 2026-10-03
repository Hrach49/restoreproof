// The paging rules TargetReader and the Cleaner share (src/graph_paging.hpp,
// W3.4 point 2), as pure functions. list_pages itself is exercised through
// TargetReader in graph_targets_test.cpp.

#include "../src/graph_paging.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <string>
#include <vector>

namespace {

const std::string kMailbox = "restoretest@example.onmicrosoft.com";
const std::string kDrive = "b!ABCdef-_123";
const std::string kFolder = "01FOLDERITEMID000000000000000000";
const std::string kGraph = "https://graph.microsoft.com/v1.0";

using Path = std::vector<std::string>;

} // namespace

// Failure paths first.
TEST_CASE("is_listed_id refuses what can't go in a URL path", "[graph][paging]")
{
    const std::string id = GENERATE(std::string{}, std::string(513, 'a'), std::string{"a/b"},
                                    std::string{"a b"}, std::string{"a?b"}, std::string{"a%2f"},
                                    std::string{"a#b"}, std::string{"a.b"}, std::string{"a\\b"},
                                    std::string{"\xC3\xA9"}, std::string{"a\nb"});
    CAPTURE(id);
    CHECK_FALSE(rp::graph::is_listed_id(id));
}

TEST_CASE("is_listed_id takes Graph's and Exchange's IDs", "[graph][paging]")
{
    const std::string id = GENERATE(std::string{"01ABCDEF"}, std::string{"AAMkAGI2-_THQAAA="},
                                    std::string{"b!x"}, std::string(512, 'Z'));
    CAPTURE(id);
    CHECK(rp::graph::is_listed_id(id));
}

TEST_CASE("the path rules refuse another resource", "[graph][paging]")
{
    using rp::graph::is_folder_path;
    using rp::graph::is_inbox_path;
    using rp::graph::is_library_root_path;
    // Another mailbox, another folder, more segments.
    CHECK_FALSE(is_inbox_path({"users", "alice@example.onmicrosoft.com", "mailfolders", "inbox",
                               "messages"},
                              kMailbox));
    CHECK_FALSE(is_inbox_path({"users", "restoretest@example.onmicrosoft.com", "mailfolders",
                               "deleteditems", "messages"},
                              kMailbox));
    CHECK_FALSE(is_inbox_path({"users", "restoretest@example.onmicrosoft.com", "messages"},
                              kMailbox));
    // Another drive, a folder's children, an item ID that isn't one.
    CHECK_FALSE(is_library_root_path({"drives", "b!other", "root", "children"}, kDrive));
    CHECK_FALSE(is_library_root_path({"drives", "b!abcdef-_123", "root:", "children"}, kDrive));
    CHECK_FALSE(is_library_root_path({"drives", "b!abcdef-_123", "items", "a.b", "children"},
                                     kDrive));
    // Another folder of the same drive.
    CHECK_FALSE(is_folder_path({"drives", "b!abcdef-_123", "items", "01other", "children"}, kDrive,
                               kFolder));
    CHECK_FALSE(is_folder_path({"drives", "b!abcdef-_123", "root", "children"}, kDrive, kFolder));
}

TEST_CASE("the path rules take the guarded target in Graph's forms", "[graph][paging]")
{
    using rp::graph::resource_path;
    CHECK(rp::graph::is_inbox_path(
        resource_path(kGraph + "/users('RestoreTest%40example.onmicrosoft.com')/mailFolders('Inbox')"
                               "/messages?%24skip=1"),
        kMailbox));
    CHECK(rp::graph::is_inbox_path(
        resource_path(kGraph + "/users/00000000-0000-4000-8000-000000000001/mailFolders/inbox/"
                               "messages"),
        kMailbox));
    CHECK(rp::graph::is_library_root_path(
        resource_path(kGraph + "/drives('" + kDrive + "')/root/children?$skiptoken=y"), kDrive));
    CHECK(rp::graph::is_folder_path(
        resource_path(kGraph + "/drives/" + kDrive + "/items/" + kFolder + "/children?$skip=1"),
        kDrive, kFolder));
    CHECK(resource_path(kGraph + "/A/b%2Fc('D')?x=1") == Path{"a", "b", "c", "d"});
}
