// The local outbox (rp/outbox.hpp; W4.6, docs/decisions.md 2026-10-07):
// queueing a signed run folder, the manifest, the retry schedule, what a flush
// checks before it sends, and the caps. Failure paths first.

#include "outbox_lab.hpp"

#include <rp/canonical_json.hpp>
#include <rp/outbox.hpp>
#include <rp/run_lock.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace rp::test::outbox_lab;

namespace {

using Lines = std::vector<std::string>;

const std::string kId = "run-0001";

rp::OutboxManifest queued_manifest()
{
    rp::OutboxManifest manifest;
    manifest.run_id = kId;
    manifest.queued_at = "2026-10-07T12:00:00Z";
    manifest.timestamped = true;
    manifest.files = {"items.csv", "result.json"};
    return manifest;
}

const std::string kQueuedText =
    R"({"attempts":0,"files":["items.csv","result.json"],"format":"restoreproof.outbox-manifest.v1",)"
    R"("last_attempt_at":null,"last_error":null,"next_attempt_at":null,)"
    R"("queued_at":"2026-10-07T12:00:00Z","run_id":"run-0001",)"
    R"("timestamp":{"code":null,"state":"timestamped"}})";

} // namespace

// --- the codes, the schedule, the time ------------------------------------------------

TEST_CASE("outbox: an upload error is one of three words or upload_http_ and three digits",
          "[outbox]")
{
    for (const char* code : {"upload_unreachable", "upload_timeout", "upload_internal",
                             "upload_http_500", "upload_http_200", "upload_http_999",
                             "upload_not_cloud"}) {
        CAPTURE(code);
        CHECK(rp::is_upload_error(code));
    }
    for (const char* code : {"", "folder_changed", "upload_http_", "upload_http_50",
                             "upload_http_5000", "upload_http_5x0", "upload_tls",
                             "UPLOAD_TIMEOUT", "xupload_http_500"}) {
        CAPTURE(code);
        CHECK_FALSE(rp::is_upload_error(code));
    }
}

TEST_CASE("outbox: the retry schedule is one minute, doubled per attempt, capped at one hour",
          "[outbox]")
{
    struct Row {
        int attempts;
        int seconds;
    };
    const Row row = GENERATE(Row{-3, 60}, Row{0, 60}, Row{1, 60}, Row{2, 120}, Row{3, 240},
                             Row{4, 480}, Row{5, 960}, Row{6, 1920}, Row{7, 3600}, Row{8, 3600},
                             Row{40, 3600}, Row{rp::kMaxUploadAttempts, 3600});
    CAPTURE(row.attempts);
    CHECK(rp::upload_retry_delay(row.attempts) == std::chrono::seconds{row.seconds});
}

TEST_CASE("outbox: a time is UTC to the whole second", "[outbox]")
{
    CHECK(rp::outbox_time_text(at()) == "2026-10-07T12:00:00Z");
    CHECK(rp::outbox_time_text(at(59) + std::chrono::milliseconds{999}) == "2026-10-07T12:00:59Z");
    CHECK(rp::outbox_time_text(at(-1)) == "2026-10-07T11:59:59Z");
}

// --- the manifest ---------------------------------------------------------------------

TEST_CASE("outbox manifest: anything but its own canonical form with exactly its keys is no "
          "manifest",
          "[outbox][manifest]")
{
    struct Row {
        const char* name;
        std::function<std::string(json)> text;
    };
    const auto patched = [](std::function<void(json&)> change) {
        return [change](json doc) {
            change(doc);
            return rp::canonical_json(doc);
        };
    };
    const Row row = GENERATE_COPY(
        Row{"not JSON", [](json) { return std::string{"{"}; }},
        Row{"empty", [](json) { return std::string{}; }},
        Row{"an array", [](json) { return std::string{"[]"}; }},
        Row{"a space", [](json doc) { return rp::canonical_json(doc) + " "; }},
        Row{"keys not sorted", [](json doc) { return nlohmann::ordered_json(doc).dump(1); }},
        Row{"a float", [](json doc) {
                std::string text = rp::canonical_json(doc);
                text.replace(text.find("\"attempts\":0"), 12, "\"attempts\":0.5");
                return text;
            }},
        Row{"a key more", patched([](json& d) { d["note"] = "x"; })},
        Row{"a key missing", patched([](json& d) { d.erase("files"); })},
        Row{"sent_at in place of a key", patched([](json& d) {
                d.erase("files");
                d["sent_at"] = "2026-10-07T12:00:00Z";
            })},
        Row{"another format", patched([](json& d) { d["format"] = "restoreproof.result.v1"; })},
        Row{"a null format", patched([](json& d) { d["format"] = nullptr; })},
        Row{"a number for the format", patched([](json& d) { d["format"] = 1; })},
        Row{"another run", patched([](json& d) { d["run_id"] = "run-0002"; })},
        Row{"queued_at null", patched([](json& d) { d["queued_at"] = nullptr; })},
        Row{"queued_at too short", patched([](json& d) { d["queued_at"] = "2026-10-07"; })},
        Row{"queued_at with a letter",
            patched([](json& d) { d["queued_at"] = "2026-10-07T12:00:0xZ"; })},
        Row{"queued_at with a space",
            patched([](json& d) { d["queued_at"] = "2026-10-07 12:00:00Z"; })},
        Row{"queued_at with an offset",
            patched([](json& d) { d["queued_at"] = "2026-10-07T12:00:00+"; })},
        Row{"next_attempt_at a number", patched([](json& d) { d["next_attempt_at"] = 5; })},
        Row{"next_attempt_at no time", patched([](json& d) { d["next_attempt_at"] = "soon"; })},
        Row{"last_attempt_at no time", patched([](json& d) { d["last_attempt_at"] = ""; })},
        Row{"last_error no code", patched([](json& d) { d["last_error"] = "upload_failed"; })},
        Row{"attempts negative", patched([](json& d) { d["attempts"] = -1; })},
        Row{"attempts too many", patched([](json& d) { d["attempts"] = 1000001; })},
        Row{"attempts a string", patched([](json& d) { d["attempts"] = "1"; })},
        Row{"timestamp a string", patched([](json& d) { d["timestamp"] = "timestamped"; })},
        Row{"timestamp with a third key", patched([](json& d) { d["timestamp"]["time"] = 1; })},
        Row{"timestamp without its state", patched([](json& d) {
                d["timestamp"].erase("state");
                d["timestamp"]["x"] = 1;
            })},
        Row{"another state", patched([](json& d) { d["timestamp"]["state"] = "stamped"; })},
        Row{"a null state", patched([](json& d) { d["timestamp"]["state"] = nullptr; })},
        Row{"an empty code", patched([](json& d) { d["timestamp"]["code"] = ""; })},
        Row{"a code of 65 characters",
            patched([](json& d) { d["timestamp"]["code"] = std::string(65, 'a'); })},
        Row{"a code with a line end", patched([](json& d) { d["timestamp"]["code"] = "a\nb"; })},
        Row{"a code that is a number", patched([](json& d) { d["timestamp"]["code"] = 7; })},
        Row{"files a string", patched([](json& d) { d["files"] = "result.json"; })},
        Row{"files with a number", patched([](json& d) { d["files"] = json::array({"a", 1}); })},
        Row{"sent_at null", patched([](json& d) { d["sent_at"] = nullptr; })},
        Row{"sent_at no time", patched([](json& d) { d["sent_at"] = "yesterday"; })});
    CAPTURE(row.name);
    const std::string text = row.text(json::parse(kQueuedText));
    CHECK_FALSE(rp::parse_manifest(text, kId));
}

TEST_CASE("outbox manifest: a queued run's text is canonical JSON with nine keys, and reads back",
          "[outbox][manifest]")
{
    const rp::OutboxManifest manifest = queued_manifest();

    CHECK(rp::manifest_text(manifest) == kQueuedText);

    const std::optional<rp::OutboxManifest> read = rp::parse_manifest(kQueuedText, kId);
    REQUIRE(read);
    CHECK(read->run_id == kId);
    CHECK(read->queued_at == "2026-10-07T12:00:00Z");
    CHECK(read->attempts == 0);
    CHECK_FALSE(read->next_attempt_at);
    CHECK_FALSE(read->last_attempt_at);
    CHECK_FALSE(read->last_error);
    CHECK(read->timestamped);
    CHECK_FALSE(read->timestamp_code);
    CHECK(read->files == Lines{"items.csv", "result.json"});
    CHECK_FALSE(read->sent_at);
    // The same text for another folder's name is not that run's manifest.
    CHECK_FALSE(rp::parse_manifest(kQueuedText, "run-0002"));
}

TEST_CASE("outbox manifest: every field is written and read back", "[outbox][manifest]")
{
    rp::OutboxManifest manifest = queued_manifest();
    manifest.attempts = rp::kMaxUploadAttempts;
    manifest.next_attempt_at = "2026-10-07T13:00:00Z";
    manifest.last_attempt_at = "2026-10-07T12:00:00Z";
    manifest.timestamped = false;
    manifest.timestamp_code = "tsa_unreachable";
    manifest.files = {};
    const std::string code = GENERATE("upload_unreachable", "upload_timeout", "upload_internal",
                                      "upload_http_500", "folder_changed");
    manifest.last_error = code;
    const bool sent = GENERATE(false, true);
    if (sent) {
        manifest.sent_at = "2026-10-07T12:30:00Z";
    }

    const std::string text = rp::manifest_text(manifest);

    CHECK_THAT(text, ContainsSubstring(R"("timestamp":{"code":"tsa_unreachable",)"
                                       R"("state":"not_timestamped"})"));
    CHECK(json::parse(text).size() == (sent ? 10u : 9u));
    const std::optional<rp::OutboxManifest> read = rp::parse_manifest(text, kId);
    REQUIRE(read);
    CHECK(rp::manifest_text(*read) == text);
    CHECK(read->attempts == rp::kMaxUploadAttempts);
    CHECK(read->last_error == code);
    CHECK(read->next_attempt_at == "2026-10-07T13:00:00Z");
    CHECK(read->last_attempt_at == "2026-10-07T12:00:00Z");
    CHECK_FALSE(read->timestamped);
    CHECK(read->timestamp_code == "tsa_unreachable");
    CHECK(read->sent_at.has_value() == sent);
}

// --- queue ----------------------------------------------------------------------------

TEST_CASE("outbox queue: a folder without result.json is never queued", "[outbox][queue]")
{
    Box box;
    const std::string what = GENERATE("no result.json", "no folder", "a run ID that isn't UTF-8");
    CAPTURE(what);
    std::string id = kId;
    path folder = box.make_run(kId);
    if (what == "no result.json") {
        std::filesystem::remove(folder / "result.json");
    } else if (what == "no folder") {
        folder = box.runs / "gone";
    } else {
        id = "run-\xff";
    }
    rp::Outbox outbox = box.outbox();

    const rp::QueueOutcome outcome = outbox.queue(folder, id, at(), true, "");

    CHECK(outcome.result == rp::QueueResult::not_complete);
    CHECK_FALSE(std::filesystem::exists(box.root));
    CHECK(outbox.queue_error(outcome, folder) ==
          "outbox error: " + utf8_of(folder) + ": no result.json; not queued");
}

TEST_CASE("outbox queue: a run already queued or already sent is refused and its folder stays",
          "[outbox][queue]")
{
    Box box;
    const bool in_sent = GENERATE(false, true);
    const path folder = box.make_run(kId);
    const std::map<std::string, std::string> before = files_of(folder);
    const path there = in_sent ? box.sent(kId) : box.queued(kId);
    std::filesystem::create_directories(there);
    rp::Outbox outbox = box.outbox();

    const rp::QueueOutcome outcome = outbox.queue(folder, kId, at(), true, "");

    CHECK(outcome.result ==
          (in_sent ? rp::QueueResult::already_sent : rp::QueueResult::already_queued));
    CHECK(outbox.queue_error(outcome, folder) ==
          "outbox error: " + utf8_of(there) + (in_sent ? ": already sent" : ": already queued"));
    CHECK(files_of(folder) == before);
    CHECK(std::filesystem::is_empty(there));
}

TEST_CASE("outbox queue: an outbox folder that can't be made stops it", "[outbox][queue]")
{
    Box box;
    const path folder = box.make_run(kId);
    // The root is a file: nothing can be made under it.
    spit(box.root, "x");
    rp::Outbox outbox = box.outbox();

    const rp::QueueOutcome outcome = outbox.queue(folder, kId, at(), true, "");

    CHECK(outcome.result == rp::QueueResult::no_outbox_folder);
    CHECK(outbox.queue_error(outcome, folder) ==
          "outbox error: " + utf8_of(box.root / "outbox") + ": the folder couldn't be made");
    CHECK(std::filesystem::exists(folder / "result.json"));
}

TEST_CASE("outbox queue: a rename that fails leaves the run folder where and as it was",
          "[outbox][queue]")
{
    Box box;
    const unsigned long code = GENERATE(17ul, 5ul);
    const path folder = box.make_run(kId);
    const std::map<std::string, std::string> before = files_of(folder);
    int writes = 0;
    box.files.move_folder = [&](const path&, const path&) { return code; };
    box.files.write_manifest = [&](const path&, std::string_view) {
        ++writes;
        return true;
    };
    rp::Outbox outbox = box.outbox();

    const rp::QueueOutcome outcome = outbox.queue(folder, kId, at(), true, "");

    CHECK(outcome.result ==
          (code == 17 ? rp::QueueResult::not_same_volume : rp::QueueResult::not_moved));
    CHECK(outcome.error == code);
    const std::string moved =
        "outbox error: " + utf8_of(folder) + ": couldn't be moved to " + utf8_of(box.queued(kId));
    CHECK(outbox.queue_error(outcome, folder) ==
          moved + (code == 17 ? ": not on the same volume" : " (error 5)"));
    CHECK(files_of(folder) == before);
    CHECK(writes == 0);
    CHECK_FALSE(std::filesystem::exists(folder / "manifest.json"));
}

TEST_CASE("outbox queue: a manifest that can't be written leaves the run queued without one",
          "[outbox][queue]")
{
    Box box;
    const path folder = box.make_run(kId);
    box.files.write_manifest = [](const path&, std::string_view) { return false; };
    rp::Outbox outbox = box.outbox();

    const rp::QueueOutcome outcome = outbox.queue(folder, kId, at(), true, "");

    CHECK(outcome.result == rp::QueueResult::queued_without_manifest);
    CHECK(outbox.queue_error(outcome, folder) ==
          "outbox error: " + utf8_of(box.queued(kId) / "manifest.json") +
              ": could not be written; the next flush makes it");
    CHECK(std::filesystem::exists(box.queued(kId) / "result.json"));
    CHECK_FALSE(std::filesystem::exists(folder));
}

TEST_CASE("outbox queue: the run folder is renamed into outbox\\<run_id> and gets its manifest",
          "[outbox][queue][acceptance]")
{
    Box box;
    const bool stamped = GENERATE(true, false);
    const path folder = box.make_run(kId, stamped);
    const std::map<std::string, std::string> before = files_of(folder);
    // Left by an earlier try, and a name no JSON string can hold: neither is
    // one of the manifest's files.
    spit(folder / "manifest.json", "old");
    const bool odd_name = rp::test::create_empty_file(folder / std::wstring{L"odd-\xD800.txt"});
    rp::Outbox outbox = box.outbox();

    const rp::QueueOutcome outcome =
        outbox.queue(folder, kId, at(90), stamped, stamped ? "ignored" : "tsa_http_status");

    REQUIRE(outcome.result == rp::QueueResult::queued);
    CHECK(outcome.folder == box.queued(kId));
    CHECK(outbox.queue_error(outcome, folder).empty());
    CHECK_FALSE(std::filesystem::exists(folder));
    // The signed files are the bytes the run wrote.
    CHECK(odd_name);
    CHECK(files_of(outcome.folder) == before);

    const rp::OutboxManifest manifest = box.manifest_of(outcome.folder);
    CHECK(manifest.run_id == kId);
    CHECK(manifest.queued_at == "2026-10-07T12:01:30Z");
    CHECK(manifest.attempts == 0);
    CHECK_FALSE(manifest.next_attempt_at);
    CHECK_FALSE(manifest.last_attempt_at);
    CHECK_FALSE(manifest.last_error);
    CHECK_FALSE(manifest.sent_at);
    CHECK(manifest.timestamped == stamped);
    CHECK(manifest.timestamp_code ==
          (stamped ? std::optional<std::string>{} : std::optional<std::string>{"tsa_http_status"}));
    Lines names{"items.csv", "result.json", "signature.json", "veeam-session.log"};
    if (stamped) {
        names.insert(names.begin() + 3, "timestamp.tst");
    }
    CHECK(manifest.files == names);
}

TEST_CASE("outbox queue: a code that is no code is a null one", "[outbox][queue]")
{
    Box box;
    const std::string code = GENERATE("", "two\nlines");
    const path folder = box.make_run(kId, false);

    const rp::QueueOutcome outcome = box.outbox().queue(folder, kId, at(), false, code);

    REQUIRE(outcome.result == rp::QueueResult::queued);
    CHECK_FALSE(box.manifest_of(outcome.folder).timestamp_code);
    CHECK_FALSE(box.manifest_of(outcome.folder).timestamped);
}

// --- prepare: before the run ----------------------------------------------------------

TEST_CASE("outbox prepare: nothing in the way is an empty line, and the outbox folder is made",
          "[outbox][queue]")
{
    Box box;
    const bool with_id = GENERATE(false, true);
    const std::optional<std::string_view> run_id =
        with_id ? std::optional<std::string_view>{kId} : std::nullopt;

    CHECK(box.outbox().prepare(box.runs, run_id).empty());

    CHECK(std::filesystem::is_directory(box.root / "outbox"));
    CHECK(std::filesystem::is_empty(box.root / "outbox"));
    CHECK_FALSE(std::filesystem::exists(box.root / "sent"));
    CHECK_FALSE(std::filesystem::exists(box.runs));
}

TEST_CASE("outbox prepare: with a run ID, a run already queued or already sent is refused before "
          "anything is made",
          "[outbox][queue]")
{
    Box box;
    const bool in_sent = GENERATE(false, true);
    const path there = in_sent ? box.sent(kId) : box.queued(kId);
    std::filesystem::create_directories(there);

    CHECK(box.outbox().prepare(box.runs, kId) ==
          "outbox error: " + utf8_of(there) + (in_sent ? ": already sent" : ": already queued") +
              "; nothing was done");
    // Without the ID (the run makes its own later), nothing is known to be in
    // the way.
    CHECK(box.outbox().prepare(box.runs, std::nullopt).empty());
    CHECK(std::filesystem::is_empty(there));
}

TEST_CASE("outbox prepare: an outbox folder that can't be made is refused", "[outbox][queue]")
{
    Box box;
    // The root is a file: nothing can be made under it.
    spit(box.root, "x");

    CHECK(box.outbox().prepare(box.runs, kId) ==
          "outbox error: " + utf8_of(box.root / "outbox") +
              ": the folder couldn't be made; nothing was done");
}

TEST_CASE("outbox prepare: a runs root on another volume than the outbox is refused; one whose "
          "volume can't be told isn't",
          "[outbox][queue]")
{
    Box box;
    std::vector<std::pair<path, path>> asked;
    std::optional<bool> answer = false;
    box.files.same_volume = [&](const path& a, const path& b) {
        asked.emplace_back(a, b);
        return answer;
    };

    CHECK(box.outbox().prepare(box.runs, kId) ==
          "outbox error: " + utf8_of(box.runs) + ": not on the same volume as " +
              utf8_of(box.root / "outbox") + "; nothing was done");

    REQUIRE(asked.size() == 1);
    CHECK(asked[0].first == box.runs);
    CHECK(asked[0].second == box.root / "outbox");
    answer = std::nullopt;
    CHECK(box.outbox().prepare(box.runs, kId).empty());
    answer = true;
    CHECK(box.outbox().prepare(box.runs, kId).empty());
    CHECK(asked.size() == 3);
}

// --- holds ----------------------------------------------------------------------------

TEST_CASE("outbox holds: anything at outbox\\<run_id> is queued, at sent\\<run_id> sent, else "
          "none; reads only",
          "[outbox][holds]")
{
    Box box;

    // Nothing there, not even the root: none, and nothing is made.
    CHECK(box.outbox().holds(kId) == rp::OutboxHolds::none);
    CHECK_FALSE(std::filesystem::exists(box.root));

    box.sent_run("was-sent", 0);
    box.queue_run("is-queued");
    // Anything at the path counts, as for queue and prepare: an empty folder
    // and a file too.
    std::filesystem::create_directories(box.queued("empty-folder"));
    spit(box.root / "outbox" / "a-file", "x");
    spit(box.root / "sent" / "sent-file", "x");
    // Both: queued is asked first, as queue and prepare ask.
    std::filesystem::create_directories(box.queued("both"));
    std::filesystem::create_directories(box.sent("both"));

    CHECK(box.outbox().holds("is-queued") == rp::OutboxHolds::queued);
    CHECK(box.outbox().holds("empty-folder") == rp::OutboxHolds::queued);
    CHECK(box.outbox().holds("a-file") == rp::OutboxHolds::queued);
    CHECK(box.outbox().holds("was-sent") == rp::OutboxHolds::sent);
    CHECK(box.outbox().holds("sent-file") == rp::OutboxHolds::sent);
    CHECK(box.outbox().holds("both") == rp::OutboxHolds::queued);
    CHECK(box.outbox().holds("another") == rp::OutboxHolds::none);
}

TEST_CASE("outbox holds: a run ID that is empty or not UTF-8 names no run", "[outbox][holds]")
{
    Box box;
    box.queue_run(kId);
    box.sent_run("was-sent", 0);

    // The empty name would be outbox\ itself, which is there.
    CHECK(box.outbox().holds("") == rp::OutboxHolds::none);
    CHECK(box.outbox().holds("run-\xff") == rp::OutboxHolds::none);
}

// --- list -----------------------------------------------------------------------------

TEST_CASE("outbox list: a root that isn't there is empty", "[outbox][list]")
{
    Box box;

    const rp::OutboxListing listing = box.outbox().list();

    CHECK(listing.readable);
    CHECK(listing.queued.empty());
    CHECK(listing.sent == 0);
    CHECK(listing.errors.empty());
    CHECK_FALSE(std::filesystem::exists(box.root));
}

TEST_CASE("outbox list: an outbox or a sent that is no folder can't be read", "[outbox][list]")
{
    Box box;
    const std::string which = GENERATE("outbox", "sent");
    std::filesystem::create_directories(box.root);
    spit(box.root / which, "x");

    CHECK_FALSE(box.outbox().list().readable);
    FakeUploader uploader;
    const rp::FlushReport report = box.outbox().flush(uploader, at());
    CHECK_FALSE(report.readable);
    CHECK(report.errors);
    CHECK(report.err == Lines{"outbox error: " + utf8_of(box.root) + ": the outbox can't be read"});
    CHECK(report.out.empty());
    CHECK(uploader.runs.empty());
}

TEST_CASE("outbox list: every folder with a result.json is a queued run, with its manifest or "
          "without; anything else isn't",
          "[outbox][list]")
{
    Box box;
    box.queue_run("run-b", 10);
    box.queue_run("run-a", 20, false);
    const path bare = box.queue_run("run-c", 30);
    spit(bare / "manifest.json", "{}");
    std::filesystem::create_directories(box.queued("stray"));
    spit(box.root / "outbox" / "note.txt", "a file");
    box.sent_run("old-1", -100);
    box.sent_run("old-2", -50);
    spit(box.root / "sent" / "note.txt", "a file");

    const rp::OutboxListing listing = box.outbox().list();

    CHECK(listing.readable);
    REQUIRE(listing.queued.size() == 3);
    CHECK(listing.queued[0].run_id == "run-a");
    REQUIRE(listing.queued[0].manifest);
    CHECK(listing.queued[0].manifest->timestamp_code == "tsa_unreachable");
    CHECK(listing.queued[1].run_id == "run-b");
    REQUIRE(listing.queued[1].manifest);
    CHECK(listing.queued[1].manifest->queued_at == text_at(10));
    CHECK(listing.queued[2].run_id == "run-c");
    CHECK_FALSE(listing.queued[2].manifest);
    CHECK(listing.sent == 2);
    CHECK(listing.errors ==
          Lines{"outbox error: " + utf8_of(box.queued("stray")) +
                ": no result.json; not a queued run"});
    // Reading changed nothing.
    CHECK(*slurp(bare / "manifest.json") == "{}");
}

// --- flush: what is never sent --------------------------------------------------------

TEST_CASE("outbox flush: a file that isn't what the run signed is never sent; the run stays "
          "queued and no attempt is counted",
          "[outbox][flush]")
{
    struct Row {
        const char* name;
        std::string file; // the one the line names
        bool stamped;
        std::function<void(const path&)> change;
    };
    const auto relist = [](std::function<void(json&)> change, bool stamped = true) {
        return [change, stamped](const path& folder) {
            json result = json::parse(*slurp(folder / "result.json"));
            change(result);
            Box::write_result(folder, result.dump(), stamped);
        };
    };
    const Row row = GENERATE_COPY(
        Row{"result.json changed", "result.json", true,
            [](const path& f) { spit(f / "result.json", *slurp(f / "result.json") + " "); }},
        Row{"result.json not JSON", "result.json", true,
            [](const path& f) { Box::write_result(f, "{", true); }},
        Row{"result.json an array", "result.json", true,
            [](const path& f) { Box::write_result(f, "[]", true); }},
        Row{"result.json without a run ID", "result.json", true,
            relist([](json& r) { r.erase("run_id"); })},
        Row{"result.json with a number for the run ID", "result.json", true,
            relist([](json& r) { r["run_id"] = 1; })},
        Row{"result.json of another run", "result.json", true,
            relist([](json& r) { r["run_id"] = "run-0002"; })},
        Row{"signature.json gone", "signature.json", true,
            [](const path& f) { std::filesystem::remove(f / "signature.json"); }},
        Row{"signature.json too large", "signature.json", true,
            [](const path& f) { spit(f / "signature.json", std::string(5000, ' ')); }},
        Row{"signature.json not an object", "signature.json", true,
            [](const path& f) { spit(f / "signature.json", "[]"); }},
        Row{"signature.json without the hash", "signature.json", true,
            [](const path& f) { spit(f / "signature.json", R"({"key_id":"k"})"); }},
        Row{"signature.json with a number for the hash", "signature.json", true,
            [](const path& f) { spit(f / "signature.json", R"({"bundle_sha256":1})"); }},
        Row{"the token gone", "timestamp.tst", true,
            [](const path& f) { std::filesystem::remove(f / "timestamp.tst"); }},
        Row{"the token no token", "timestamp.tst", true,
            [](const path& f) { spit(f / "timestamp.tst", "not DER"); }},
        Row{"the token over another hash", "timestamp.tst", true,
            [](const path& f) { spit(f / "timestamp.tst", token_over("another result")); }},
        Row{"a token beside a run that got none", "timestamp.tst", false,
            [](const path& f) { spit(f / "timestamp.tst", token_over("x")); }},
        Row{"no attachments key", "result.json", true,
            relist([](json& r) { r.erase("attachments"); })},
        Row{"attachments a string", "result.json", true,
            relist([](json& r) { r["attachments"] = "items.csv"; })},
        Row{"an attachment that is no object", "result.json", true,
            relist([](json& r) { r["attachments"][0] = "items.csv"; })},
        Row{"an attachment without its name", "result.json", true,
            relist([](json& r) { r["attachments"][0].erase("name"); })},
        Row{"an attachment with a number for its name", "result.json", true,
            relist([](json& r) { r["attachments"][0]["name"] = 1; })},
        Row{"an attachment without its hash", "result.json", true,
            relist([](json& r) { r["attachments"][0].erase("sha256"); })},
        Row{"an attachment with a number for its hash", "result.json", true,
            relist([](json& r) { r["attachments"][0]["sha256"] = 1; })},
        Row{"an attachment without its size", "result.json", true,
            relist([](json& r) { r["attachments"][0].erase("size_bytes"); })},
        Row{"an attachment with a negative size", "result.json", true,
            relist([](json& r) { r["attachments"][0]["size_bytes"] = -1; })},
        Row{"an attachment outside the folder", "result.json", true,
            relist([](json& r) { r["attachments"][0]["name"] = "..\\run-0002\\items.csv"; })},
        Row{"the result as its own attachment", "result.json", true,
            relist([](json& r) { r["attachments"][0]["name"] = "result.json"; })},
        Row{"the signature as an attachment", "result.json", true,
            relist([](json& r) { r["attachments"][0]["name"] = "signature.json"; })},
        Row{"the token as an attachment", "result.json", true,
            relist([](json& r) { r["attachments"][0]["name"] = "timestamp.tst"; })},
        Row{"the manifest as an attachment", "result.json", true,
            relist([](json& r) { r["attachments"][0]["name"] = "manifest.json"; })},
        Row{"an attachment gone", "items.csv", true,
            [](const path& f) { std::filesystem::remove(f / "items.csv"); }},
        Row{"a folder in an attachment's place", "items.csv", true,
            [](const path& f) {
                std::filesystem::remove(f / "items.csv");
                std::filesystem::create_directory(f / "items.csv");
            }},
        Row{"an attachment longer", "veeam-session.log", true,
            [](const path& f) { spit(f / "veeam-session.log", std::string(200, 'x')); }},
        Row{"an attachment shorter", "items.csv", true,
            [](const path& f) { spit(f / "items.csv", "index"); }},
        Row{"an attachment with one byte changed", "items.csv", true, [](const path& f) {
                std::string bytes = *slurp(f / "items.csv");
                bytes[0] = 'I';
                spit(f / "items.csv", bytes);
            }});
    CAPTURE(row.name);
    Box box;
    const path folder = box.queue_run(kId, 0, row.stamped);
    row.change(folder);
    const std::map<std::string, std::string> before = files_of(folder);
    FakeUploader uploader;

    const rp::FlushReport report = box.outbox().flush(uploader, at(100));

    CHECK(uploader.runs.empty());
    CHECK(report.readable);
    CHECK(report.errors);
    CHECK(report.err == Lines{"outbox error: " + utf8_of(folder) + ": " + row.file +
                              " changed since it was signed"});
    CHECK(report.out == Lines{"kept run-0001: folder_changed"});
    CHECK(report.queued == 1);
    CHECK(report.sent == 0);
    CHECK(files_of(folder) == before);
    const rp::OutboxManifest manifest = box.manifest_of(folder);
    CHECK(manifest.last_error == "folder_changed");
    CHECK(manifest.attempts == 0);
    CHECK_FALSE(manifest.last_attempt_at);
    CHECK_FALSE(manifest.next_attempt_at);
    CHECK_FALSE(std::filesystem::exists(box.sent(kId)));
}

TEST_CASE("outbox flush: a changed run's manifest is written once; the next flush finds the "
          "same text and rewrites nothing",
          "[outbox][flush]")
{
    Box box;
    const path folder = box.queue_run(kId);
    spit(folder / "items.csv", "index");
    int writes = 0;
    box.files.write_manifest = [&](const path& file, std::string_view text) {
        ++writes;
        spit(file, text);
        return true;
    };
    FakeUploader uploader;

    const rp::FlushReport first = box.outbox().flush(uploader, at(100));
    const rp::FlushReport second = box.outbox().flush(uploader, at(200));

    CHECK(writes == 1);
    CHECK(first.out == Lines{"kept run-0001: folder_changed"});
    CHECK(second.out == first.out);
    CHECK(second.err == first.err);
    CHECK(second.errors);
    CHECK(box.manifest_of(folder).last_error == "folder_changed");
    CHECK(uploader.runs.empty());
}

TEST_CASE("outbox flush: a file that is there but can't be read now is said so, never called "
          "changed; nothing is sent, nothing is written, and the next flush tries again",
          "[outbox][flush]")
{
    const std::string file =
        GENERATE("result.json", "signature.json", "timestamp.tst", "items.csv");
    CAPTURE(file);
    Box box;
    const path folder = box.queue_run(kId);
    const std::string manifest_before = *slurp(folder / "manifest.json");
    int writes = 0;
    box.files.write_manifest = [&](const path&, std::string_view) {
        ++writes;
        return true;
    };
    FakeUploader uploader;
    // Another handle holds the file open and shares nothing: it is there, a
    // file, and can't be opened to read.
    const HANDLE holder = CreateFileW((folder / file).c_str(), GENERIC_READ, 0, nullptr,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(holder != INVALID_HANDLE_VALUE);

    const rp::FlushReport report = box.outbox().flush(uploader, at(100));

    CloseHandle(holder);
    CHECK(uploader.runs.empty());
    CHECK(report.errors);
    CHECK(report.err ==
          Lines{"outbox error: " + utf8_of(folder) + ": " + file + " couldn't be read"});
    CHECK(report.out == Lines{"kept run-0001: not_read"});
    CHECK(report.queued == 1);
    CHECK(writes == 0);
    CHECK(*slurp(folder / "manifest.json") == manifest_before);
    CHECK(box.manifest_of(folder).attempts == 0);
    CHECK_FALSE(box.manifest_of(folder).last_error);
    // Readable again, it is sent.
    CHECK(box.outbox().flush(uploader, at(200)).out == Lines{"sent run-0001"});
    CHECK(uploader.runs == std::vector<std::string>{kId});
}

TEST_CASE("outbox flush: a folder under outbox that holds no result.json is no queued run, and "
          "is left alone",
          "[outbox][flush]")
{
    Box box;
    std::filesystem::create_directories(box.queued("half"));
    spit(box.queued("half") / "items.csv", "x");
    FakeUploader uploader;

    const rp::FlushReport report = box.outbox().flush(uploader, at());

    CHECK(report.err == Lines{"outbox error: " + utf8_of(box.queued("half")) +
                              ": no result.json; not a queued run"});
    CHECK(report.errors);
    CHECK(report.out.empty());
    CHECK(report.queued == 0);
    CHECK(uploader.runs.empty());
    CHECK(*slurp(box.queued("half") / "items.csv") == "x");
    CHECK_FALSE(std::filesystem::exists(box.queued("half") / "manifest.json"));
}

TEST_CASE("outbox flush: a run whose folder is already under sent is not sent again",
          "[outbox][flush]")
{
    Box box;
    const path folder = box.queue_run(kId);
    std::filesystem::create_directories(box.sent(kId));
    FakeUploader uploader;

    const rp::FlushReport report = box.outbox().flush(uploader, at());

    CHECK(uploader.runs.empty());
    CHECK(report.err ==
          Lines{"outbox warning: " + utf8_of(box.sent(kId)) +
                    ": no readable manifest.json; not pruned",
                "outbox error: " + utf8_of(box.sent(kId)) + ": already sent"});
    CHECK(report.queued == 1);
    CHECK(box.manifest_of(folder).attempts == 0);
}

// --- flush: a failed attempt ----------------------------------------------------------

TEST_CASE("outbox flush: a failed attempt is counted, its code kept and the next one scheduled; "
          "the folder is unchanged",
          "[outbox][flush]")
{
    struct Row {
        const char* name;
        std::optional<rp::UploadAnswer> answer; // nullopt: the uploader throws
        std::string code;
    };
    const Row row = GENERATE(
        Row{"500", failed("upload_http_500"), "upload_http_500"},
        Row{"a 200 is not a 202", failed("upload_http_200"), "upload_http_200"},
        Row{"unreachable", failed("upload_unreachable"), "upload_unreachable"},
        Row{"a timeout", failed("upload_timeout"), "upload_timeout"},
        Row{"the uploader's own failure", failed("upload_internal"), "upload_internal"},
        Row{"a word that is no code", failed("the cloud said no"), "upload_internal"},
        Row{"no word", failed(""), "upload_internal"},
        Row{"the uploader throws", std::nullopt, "upload_internal"});
    CAPTURE(row.name);
    Box box;
    const path folder = box.queue_run(kId);
    const std::map<std::string, std::string> before = files_of(folder);
    FakeUploader uploader;
    if (row.answer) {
        uploader.answers = {*row.answer};
    } else {
        uploader.at_upload = [] { throw std::runtime_error("boom"); };
    }

    const rp::FlushReport report = box.outbox().flush(uploader, at(100));

    CHECK(uploader.runs == Lines{kId});
    CHECK(report.out == Lines{"kept run-0001: " + row.code + "; attempt 1, next at " + text_at(160)});
    CHECK(report.err.empty());
    CHECK_FALSE(report.errors);
    CHECK(report.queued == 1);
    CHECK(report.sent == 0);
    CHECK(files_of(folder) == before);
    const rp::OutboxManifest manifest = box.manifest_of(folder);
    CHECK(manifest.attempts == 1);
    CHECK(manifest.last_error == row.code);
    CHECK(manifest.last_attempt_at == text_at(100));
    CHECK(manifest.next_attempt_at == text_at(160));
    CHECK(manifest.queued_at == text_at(0));
    CHECK_FALSE(manifest.sent_at);
}

TEST_CASE("outbox flush: a run is not tried before its next attempt is due, and each failure "
          "doubles the wait up to an hour",
          "[outbox][flush]")
{
    Box box;
    const path folder = box.queue_run(kId);
    FakeUploader uploader;
    uploader.answers = {failed("upload_unreachable")};
    long long now = 0;
    const std::vector<long long> waits{60, 120, 240, 480, 960, 1920, 3600, 3600};
    for (std::size_t n = 0; n < waits.size(); ++n) {
        CAPTURE(n);
        // Due: tried, and the next wait is the table's.
        const rp::FlushReport tried = box.outbox().flush(uploader, at(now));
        REQUIRE(uploader.runs.size() == n + 1);
        CHECK(tried.out ==
              Lines{"kept run-0001: upload_unreachable; attempt " + std::to_string(n + 1) +
                    ", next at " + text_at(now + waits[n])});
        CHECK(box.manifest_of(folder).attempts == static_cast<int>(n + 1));
        // One second before it is due: not tried.
        const rp::FlushReport early = box.outbox().flush(uploader, at(now + waits[n] - 1));
        CHECK(uploader.runs.size() == n + 1);
        CHECK(early.out == Lines{"waiting run-0001: next at " + text_at(now + waits[n])});
        CHECK(early.queued == 1);
        CHECK(early.err.empty());
        // At the second it is due, the next round tries it.
        now += waits[n];
    }
}

TEST_CASE("outbox flush: a manifest that can't be written after a failed attempt is said",
          "[outbox][flush]")
{
    Box box;
    const path folder = box.queue_run(kId);
    box.files.write_manifest = [](const path&, std::string_view) { return false; };
    FakeUploader uploader;
    uploader.answers = {failed("upload_http_503")};

    const rp::FlushReport report = box.outbox().flush(uploader, at());

    CHECK(report.err == Lines{"outbox error: " + utf8_of(folder / "manifest.json") +
                              ": could not be written"});
    CHECK(report.out ==
          Lines{"kept run-0001: upload_http_503; attempt 1, next at " + text_at(60)});
    CHECK(report.queued == 1);
    CHECK(box.manifest_of(folder).attempts == 0);
}

TEST_CASE("outbox flush: the attempts stop counting at their limit", "[outbox][flush]")
{
    Box box;
    const path folder = box.queue_run(kId);
    rp::OutboxManifest manifest = box.manifest_of(folder);
    manifest.attempts = rp::kMaxUploadAttempts;
    spit(folder / "manifest.json", rp::manifest_text(manifest));
    FakeUploader uploader;
    uploader.answers = {failed("upload_timeout")};

    box.outbox().flush(uploader, at());

    CHECK(box.manifest_of(folder).attempts == rp::kMaxUploadAttempts);
    CHECK(box.manifest_of(folder).next_attempt_at == text_at(3600));
}

// --- flush: sent ----------------------------------------------------------------------

TEST_CASE("outbox flush: 500 then 202: the run stays queued, then is sent and moved to sent with "
          "its files as the run made them",
          "[outbox][flush][acceptance]")
{
    Box box;
    const bool stamped = GENERATE(true, false);
    const path folder = box.queue_run(kId, 0, stamped);
    const std::map<std::string, std::string> before = files_of(folder);
    FakeUploader uploader;
    uploader.answers = {failed("upload_http_500"), {true, {}}};

    const rp::FlushReport first = box.outbox().flush(uploader, at(10));
    CHECK(first.queued == 1);
    CHECK(std::filesystem::exists(folder / "result.json"));

    const rp::FlushReport second = box.outbox().flush(uploader, at(70));

    CHECK(second.out == Lines{"sent run-0001"});
    CHECK(second.err.empty());
    CHECK(second.queued == 0);
    CHECK(second.sent == 1);
    CHECK_FALSE(std::filesystem::exists(folder));
    CHECK(files_of(box.sent(kId)) == before);
    const rp::OutboxManifest manifest = box.manifest_of(box.sent(kId));
    CHECK(manifest.sent_at == text_at(70));
    CHECK(manifest.attempts == 2);
    CHECK(manifest.last_attempt_at == text_at(70));
    CHECK_FALSE(manifest.last_error);
    CHECK_FALSE(manifest.next_attempt_at);
    CHECK(manifest.queued_at == text_at(0));
    CHECK(manifest.timestamped == stamped);

    // What was sent, both times: the files' own bytes, in the contract's order.
    REQUIRE(uploader.parts.size() == 2);
    CHECK(uploader.runs == Lines{kId, kId});
    for (const std::vector<rp::UploadPart>& parts : uploader.parts) {
        Lines names;
        for (const rp::UploadPart& part : parts) {
            names.push_back(part.name);
            CHECK(part.bytes == before.at(part.filename));
        }
        CHECK(names == (stamped ? Lines{"result", "signature", "timestamp", "items.csv",
                                        "veeam-session.log"}
                                : Lines{"result", "signature", "items.csv", "veeam-session.log"}));
        CHECK(parts[0].filename == "result.json");
        CHECK(parts[0].content_type == "application/json");
        CHECK(parts[1].filename == "signature.json");
        CHECK(parts[1].content_type == "application/json");
        CHECK(parts[2].filename == (stamped ? "timestamp.tst" : "items.csv"));
        CHECK(parts[2].content_type == "application/octet-stream");
        CHECK(parts.back().filename == "veeam-session.log");
    }
    // The manifest is never one of them.
    // A third flush has nothing to do.
    const rp::FlushReport third = box.outbox().flush(uploader, at(80));
    CHECK(third.out.empty());
    CHECK(third.queued == 0);
    CHECK(third.sent == 1);
    CHECK(uploader.runs.size() == 2);
}

TEST_CASE("outbox flush: a result that lists no attachments is sent with its own files only",
          "[outbox][flush]")
{
    Box box;
    const path run = box.make_run(kId, false);
    std::filesystem::remove(run / "items.csv");
    std::filesystem::remove(run / "veeam-session.log");
    Box::write_result(run, R"({"attachments":null,"run_id":"run-0001"})", false);
    REQUIRE(box.outbox().queue(run, kId, at(), false, "").result == rp::QueueResult::queued);
    FakeUploader uploader;

    const rp::FlushReport report = box.outbox().flush(uploader, at());

    CHECK(report.out == Lines{"sent run-0001"});
    REQUIRE(uploader.parts.size() == 1);
    CHECK(uploader.parts[0].size() == 2);
}

TEST_CASE("outbox flush: the oldest queued run goes first, the run ID deciding a tie; one run's "
          "failure doesn't stop the next",
          "[outbox][flush]")
{
    Box box;
    box.queue_run("run-c", 5);
    box.queue_run("run-a", 30);
    box.queue_run("run-b", 5);
    box.queue_run("run-d", 1);
    FakeUploader uploader;
    uploader.answers = {{true, {}}, failed("upload_http_500"), {true, {}}};

    const rp::FlushReport report = box.outbox().flush(uploader, at(100));

    CHECK(uploader.runs == Lines{"run-d", "run-b", "run-c", "run-a"});
    CHECK(report.out == Lines{"sent run-d",
                              "kept run-b: upload_http_500; attempt 1, next at " + text_at(160),
                              "sent run-c", "sent run-a"});
    CHECK(report.queued == 1);
    CHECK(report.sent == 3);
}

TEST_CASE("outbox flush: a queued run without a readable manifest gets a new one and is sent",
          "[outbox][flush]")
{
    Box box;
    const std::string what = GENERATE("gone", "damaged");
    const bool stamped = GENERATE(true, false);
    const path folder = box.queue_run(kId, 0, stamped);
    if (what == "gone") {
        std::filesystem::remove(folder / "manifest.json");
    } else {
        spit(folder / "manifest.json", "{\"attempts\":");
    }
    FakeUploader uploader;
    uploader.answers = {failed("upload_timeout")};

    const rp::FlushReport report = box.outbox().flush(uploader, at(500));

    CHECK(uploader.runs == Lines{kId});
    CHECK(report.err ==
          Lines{"outbox warning: " + utf8_of(folder) + ": manifest.json was made again"});
    CHECK_FALSE(report.errors);
    CHECK(uploader.parts[0].size() == (stamped ? 5u : 4u));
    const rp::OutboxManifest manifest = box.manifest_of(folder);
    CHECK(manifest.queued_at == text_at(500));
    CHECK(manifest.attempts == 1);
    CHECK(manifest.timestamped == stamped);
    CHECK_FALSE(manifest.timestamp_code);
    CHECK(std::ranges::find(manifest.files, "manifest.json") == manifest.files.end());
    CHECK(std::ranges::find(manifest.files, "result.json") != manifest.files.end());
}

TEST_CASE("outbox flush: a 202 whose manifest can't be written leaves the run queued",
          "[outbox][flush]")
{
    Box box;
    const path folder = box.queue_run(kId);
    box.files.write_manifest = [](const path&, std::string_view) { return false; };
    FakeUploader uploader;

    const rp::FlushReport report = box.outbox().flush(uploader, at());

    CHECK(report.err == Lines{"outbox error: " + utf8_of(folder) +
                              ": uploaded, but manifest.json couldn't be written"});
    CHECK(report.out.empty());
    CHECK(report.queued == 1);
    CHECK(report.sent == 0);
    CHECK(std::filesystem::exists(folder / "result.json"));
    CHECK_FALSE(box.manifest_of(folder).sent_at);
}

TEST_CASE("outbox flush: a 202 whose folder can't be moved is not sent again; the next flush "
          "only moves it",
          "[outbox][flush]")
{
    Box box;
    const path folder = box.queue_run(kId);
    const std::map<std::string, std::string> before = files_of(folder);
    box.files.move_folder = [](const path&, const path&) { return 5ul; };
    FakeUploader uploader;

    const rp::FlushReport report = box.outbox().flush(uploader, at(10));

    CHECK(report.err == Lines{"outbox error: " + utf8_of(folder) +
                              ": uploaded, but couldn't be moved to sent (error 5)"});
    CHECK(report.out.empty());
    CHECK(report.queued == 1);
    CHECK(report.sent == 0);
    CHECK(box.manifest_of(folder).sent_at == text_at(10));

    // Still refused: said again, and not uploaded again.
    const rp::FlushReport again = box.outbox().flush(uploader, at(20));
    CHECK(again.queued == 1);
    CHECK(again.err == report.err);

    box.files.move_folder = nullptr;
    const rp::FlushReport later = box.outbox().flush(uploader, at(4000));

    CHECK(later.out == Lines{"moved run-0001"});
    CHECK(later.err.empty());
    CHECK(later.queued == 0);
    CHECK(later.sent == 1);
    CHECK(uploader.runs == Lines{kId});
    CHECK(files_of(box.sent(kId)) == before);
    CHECK(box.manifest_of(box.sent(kId)).sent_at == text_at(10));
}

TEST_CASE("outbox flush: a stop is asked before each queued run; after it no upload is started "
          "and every run left is still counted",
          "[outbox][flush][stop]")
{
    Box box;
    box.queue_run("run-a", 1);
    box.queue_run("run-b", 2);
    box.queue_run("run-c", 3);
    box.sent_run("old", -31LL * 24 * 3600);
    FakeUploader uploader;
    // How many runs are let through before the stop.
    const int let_through = GENERATE(0, 1, 2);
    CAPTURE(let_through);
    int asked = 0;

    const rp::FlushReport report =
        box.outbox().flush(uploader, at(100), [&] { return ++asked > let_through; });

    const Lines all{"run-a", "run-b", "run-c"};
    CHECK(uploader.runs == Lines(all.begin(), all.begin() + let_through));
    // The caps come before the uploads, and so before the first question.
    Lines out{"pruned old"};
    for (int n = 0; n < let_through; ++n) {
        out.push_back("sent " + all[static_cast<std::size_t>(n)]);
    }
    CHECK(report.out == out);
    CHECK(report.err.empty());
    CHECK(report.stopped);
    CHECK(report.queued == static_cast<std::size_t>(3 - let_through));
    CHECK(report.sent == static_cast<std::size_t>(let_through));
    // Asked once per run until it says yes, then never again.
    CHECK(asked == let_through + 1);
    for (int n = let_through; n < 3; ++n) {
        const std::string& id = all[static_cast<std::size_t>(n)];
        CHECK(box.manifest_of(box.queued(id)).attempts == 0);
    }
}

TEST_CASE("outbox flush: after a stop a run that was uploaded and only has to be moved stays "
          "queued too",
          "[outbox][flush][stop]")
{
    Box box;
    const path folder = box.queue_run(kId);
    box.files.move_folder = [](const path&, const path&) { return 5ul; };
    FakeUploader uploader;
    REQUIRE(box.outbox().flush(uploader, at(10)).queued == 1);
    REQUIRE(box.manifest_of(folder).sent_at == text_at(10));
    box.files.move_folder = nullptr;

    const rp::FlushReport report = box.outbox().flush(uploader, at(20), [] { return true; });

    CHECK(report.stopped);
    CHECK(report.out.empty());
    CHECK(report.err.empty());
    CHECK(report.queued == 1);
    CHECK(report.sent == 0);
    CHECK(std::filesystem::exists(folder));
}

TEST_CASE("outbox flush: a stop that never comes, and no stop function, change nothing",
          "[outbox][flush][stop]")
{
    Box box;
    box.queue_run("run-a", 1);
    box.queue_run("run-b", 2);
    FakeUploader uploader;
    const bool with_function = GENERATE(false, true);
    int asked = 0;

    const rp::FlushReport report =
        with_function ? box.outbox().flush(uploader, at(100), [&] { return ++asked, false; })
                      : box.outbox().flush(uploader, at(100));

    CHECK(report.out == Lines{"sent run-a", "sent run-b"});
    CHECK_FALSE(report.stopped);
    CHECK(report.queued == 0);
    CHECK(asked == (with_function ? 2 : 0));
}

// --- the flush mutex ------------------------------------------------------------------

TEST_CASE("the flush lock: held elsewhere is null; one a dead flush left is taken at the second "
          "try",
          "[outbox][flush][lock]")
{
    int calls = 0;

    SECTION("free: taken at the first try")
    {
        const std::unique_ptr<rp::RunLock> lock = rp::take_outbox_flush_lock([&] {
            ++calls;
            return std::make_unique<rp::RunLock>();
        });
        CHECK(lock);
        CHECK(calls == 1);
    }
    SECTION("held by another flush: null, and not asked again")
    {
        const std::unique_ptr<rp::RunLock> lock =
            rp::take_outbox_flush_lock([&]() -> std::unique_ptr<rp::RunLock> {
                ++calls;
                return nullptr;
            });
        CHECK_FALSE(lock);
        CHECK(calls == 1);
    }
    SECTION("abandoned: the second try has it")
    {
        const std::unique_ptr<rp::RunLock> lock =
            rp::take_outbox_flush_lock([&]() -> std::unique_ptr<rp::RunLock> {
                if (++calls == 1) {
                    throw rp::AbandonedRunLock();
                }
                return std::make_unique<rp::RunLock>();
            });
        CHECK(lock);
        CHECK(calls == 2);
    }
    SECTION("abandoned, and taken by another flush before the second try: null")
    {
        const std::unique_ptr<rp::RunLock> lock =
            rp::take_outbox_flush_lock([&]() -> std::unique_ptr<rp::RunLock> {
                if (++calls == 1) {
                    throw rp::AbandonedRunLock();
                }
                return nullptr;
            });
        CHECK_FALSE(lock);
        CHECK(calls == 2);
    }
}

// --- flush: the caps ------------------------------------------------------------------

TEST_CASE("outbox flush: sent runs older than 30 days are deleted, to the second",
          "[outbox][prune]")
{
    Box box;
    const long long days30 = 30LL * 24 * 3600;
    box.sent_run("older", -days30 - 1);
    box.sent_run("on-the-day", -days30);
    box.sent_run("newer", -days30 + 1);
    box.sent_run("oldest", -days30 * 3);
    const path queued = box.queue_run(kId, -days30 * 4);
    FakeUploader uploader;
    uploader.answers = {failed("upload_timeout")};

    const rp::FlushReport report = box.outbox().flush(uploader, at());

    CHECK(report.out == Lines{"pruned oldest", "pruned older",
                              "kept run-0001: upload_timeout; attempt 1, next at " + text_at(60)});
    CHECK(report.err.empty());
    CHECK(report.sent == 2);
    CHECK_FALSE(std::filesystem::exists(box.sent("older")));
    CHECK_FALSE(std::filesystem::exists(box.sent("oldest")));
    CHECK(std::filesystem::exists(box.sent("on-the-day")));
    CHECK(std::filesystem::exists(box.sent("newer")));
    // However old, a queued run is never pruned.
    CHECK(std::filesystem::exists(queued / "result.json"));
}

TEST_CASE("outbox flush: over 500 MB the oldest sent runs go until it fits; the queue never does",
          "[outbox][prune]")
{
    struct Row {
        const char* name;
        std::map<std::string, std::uintmax_t> mb; // by folder name
        Lines pruned;
        bool warned;
    };
    const Row row = GENERATE(
        Row{"under the cap", {{"q", 100}, {"s1", 200}, {"s2", 200}}, {}, false},
        Row{"at the cap", {{"q", 100}, {"s1", 200}, {"s2", 200}, {"s3", 0}}, {}, false},
        Row{"one over: the oldest goes", {{"q", 101}, {"s1", 200}, {"s2", 200}}, {"s1"}, false},
        Row{"two go", {{"q", 400}, {"s1", 150}, {"s2", 150}, {"s3", 100}}, {"s1", "s2"}, false},
        Row{"all of sent goes and the queue is still over",
            {{"q", 501}, {"s1", 1}, {"s2", 1}}, {"s1", "s2"}, true},
        Row{"the queue alone at the cap", {{"q", 500}}, {}, false});
    CAPTURE(row.name);
    Box box;
    const path queued = box.queue_run("q");
    long long sent_at = -1000;
    for (const auto& [name, mb] : row.mb) {
        if (name != "q") {
            box.sent_run(name, sent_at += 10);
        }
    }
    box.files.folder_bytes = [&](const path& folder) -> std::optional<std::uintmax_t> {
        return row.mb.at(utf8_of(folder.filename())) * 1024u * 1024u;
    };
    FakeUploader uploader;
    uploader.answers = {failed("upload_timeout")};

    const rp::FlushReport report = box.outbox().flush(uploader, at());

    Lines out;
    for (const std::string& name : row.pruned) {
        out.push_back("pruned " + name);
        CHECK_FALSE(std::filesystem::exists(box.sent(name)));
    }
    out.push_back("kept q: upload_timeout; attempt 1, next at " + text_at(60));
    CHECK(report.out == out);
    CHECK(report.err == (row.warned ? Lines{"outbox warning: the outbox holds 501 MB, over the "
                                            "500 MB cap"}
                                    : Lines{}));
    CHECK_FALSE(report.errors);
    CHECK(report.sent == row.mb.size() - 1 - row.pruned.size());
    CHECK(std::filesystem::exists(queued / "result.json"));
}

TEST_CASE("outbox flush: a sent folder with no readable manifest is never deleted, and one that "
          "can't be removed is said",
          "[outbox][prune]")
{
    Box box;
    const long long days40 = 40LL * 24 * 3600;
    std::filesystem::create_directories(box.sent("undated"));
    spit(box.sent("undated") / "result.json", "{}");
    // A manifest without sent_at: a queued run's, in the wrong place.
    box.sent_run("queued-shape", -days40);
    rp::OutboxManifest manifest = box.manifest_of(box.sent("queued-shape"));
    manifest.sent_at.reset();
    spit(box.sent("queued-shape") / "manifest.json", rp::manifest_text(manifest));
    box.sent_run("stuck", -days40);
    box.sent_run("old", -days40 + 1);
    // Sizes that can't be read count as nothing; everything is over the age.
    box.files.folder_bytes = [](const path&) { return std::optional<std::uintmax_t>{}; };
    box.files.remove_folder = [](const path& folder) {
        if (folder.filename() == "stuck") {
            return false;
        }
        std::filesystem::remove_all(folder);
        return true;
    };
    FakeUploader uploader;

    const rp::FlushReport report = box.outbox().flush(uploader, at());

    CHECK(report.out == Lines{"pruned old"});
    CHECK(report.err ==
          Lines{"outbox warning: " + utf8_of(box.sent("queued-shape")) +
                    ": no readable manifest.json; not pruned",
                "outbox warning: " + utf8_of(box.sent("undated")) +
                    ": no readable manifest.json; not pruned",
                "outbox warning: " + utf8_of(box.sent("stuck")) + ": couldn't be removed"});
    CHECK_FALSE(report.errors);
    CHECK(report.sent == 3);
    CHECK(std::filesystem::exists(box.sent("undated") / "result.json"));
    CHECK(std::filesystem::exists(box.sent("queued-shape")));
    CHECK(std::filesystem::exists(box.sent("stuck")));
}

TEST_CASE("outbox flush: with the real file system a sent run over the age is removed whole",
          "[outbox][prune]")
{
    Box box;
    const path old = box.sent_run("old", -31LL * 24 * 3600);
    std::filesystem::create_directories(old / "inner");
    spit(old / "inner" / "x.bin", std::string(1000, 'x'));
    FakeUploader uploader;

    const rp::FlushReport report = box.outbox().flush(uploader, at());

    CHECK(report.out == Lines{"pruned old"});
    CHECK(report.sent == 0);
    CHECK_FALSE(std::filesystem::exists(old));
}


// --- W5.1: the Cloud's answers (docs/decisions.md 2026-10-15, point 8) ----------------

TEST_CASE("outbox: 400, 404, 409, 415 and 422 are the Cloud's refusals for good; nothing else is",
          "[outbox][w51]")
{
    for (const char* code : {"upload_http_400", "upload_http_404", "upload_http_409",
                             "upload_http_415", "upload_http_422"}) {
        CAPTURE(code);
        CHECK(rp::is_refused_for_good(code));
    }
    for (const char* code : {"upload_http_401", "upload_http_411", "upload_http_413",
                             "upload_http_500", "upload_http_502", "upload_http_200",
                             "upload_not_cloud", "upload_timeout", "upload_unreachable",
                             "upload_internal", "folder_changed", ""}) {
        CAPTURE(code);
        CHECK_FALSE(rp::is_refused_for_good(code));
    }
}

TEST_CASE("outbox flush: a refusal for good moves the run whole to failed\\, never to be sent again",
          "[outbox][flush][w51]")
{
    const std::string code = GENERATE("upload_http_400", "upload_http_404", "upload_http_409",
                                      "upload_http_415", "upload_http_422");
    CAPTURE(code);
    Box box;
    const path folder = box.queue_run(kId);
    const std::map<std::string, std::string> before = files_of(folder);
    FakeUploader uploader;
    uploader.answers = {failed(code)};

    const rp::FlushReport report = box.outbox().flush(uploader, at(100));

    CHECK(uploader.runs == Lines{kId});
    CHECK(report.out == Lines{"failed run-0001: " + code});
    CHECK(report.err ==
          Lines{"outbox error: run-0001: refused by the Cloud (" + code + "); moved to failed"});
    CHECK(report.errors);
    CHECK(report.queued == 0);
    CHECK(report.failed == 1);
    CHECK(report.sent == 0);
    CHECK_FALSE(std::filesystem::exists(folder));
    // The signed files as they were; only the manifest says what happened.
    std::map<std::string, std::string> after = files_of(box.refused(kId));
    std::map<std::string, std::string> before_files = before;
    after.erase("manifest.json");
    before_files.erase("manifest.json");
    CHECK(after == before_files);
    const rp::OutboxManifest manifest = box.manifest_of(box.refused(kId));
    CHECK(manifest.attempts == 1);
    CHECK(manifest.last_error == code);
    CHECK(manifest.last_attempt_at == text_at(100));
    CHECK_FALSE(manifest.next_attempt_at);
    CHECK_FALSE(manifest.sent_at);

    // Never tried again, and counted at every flush.
    const rp::FlushReport again = box.outbox().flush(uploader, at(100000));
    CHECK(uploader.runs == Lines{kId});
    CHECK(again.out.empty());
    CHECK(again.err.empty());
    CHECK(again.failed == 1);
    CHECK(again.queued == 0);
}

TEST_CASE("outbox flush: 411, 413 and a 5xx are retried by the schedule as before", "[outbox][flush][w51]")
{
    const std::string code = GENERATE("upload_http_411", "upload_http_413", "upload_http_503",
                                      "upload_not_cloud");
    CAPTURE(code);
    Box box;
    box.queue_run(kId);
    FakeUploader uploader;
    uploader.answers = {failed(code)};

    const rp::FlushReport report = box.outbox().flush(uploader, at(100));

    CHECK(report.out == Lines{"kept run-0001: " + code + "; attempt 1, next at " + text_at(160)});
    CHECK(report.queued == 1);
    CHECK(report.failed == 0);
    CHECK(box.manifest_of(box.queued(kId)).last_error == code);
}

TEST_CASE("outbox flush: a refused run whose move fails stays queued; the next flush only moves it",
          "[outbox][flush][w51]")
{
    Box box;
    const path folder = box.queue_run(kId);
    box.files.move_folder = [](const path&, const path&) { return 5ul; };
    FakeUploader uploader;
    uploader.answers = {failed("upload_http_409")};

    const rp::FlushReport report = box.outbox().flush(uploader, at(10));

    CHECK(report.out == Lines{"kept run-0001: upload_http_409"});
    CHECK(report.err == Lines{"outbox error: run-0001: refused by the Cloud (upload_http_409), but "
                              "couldn't be moved to failed (error 5)"});
    CHECK(report.queued == 1);
    CHECK(report.failed == 0);
    const rp::OutboxManifest manifest = box.manifest_of(folder);
    CHECK(manifest.last_error == "upload_http_409");
    CHECK_FALSE(manifest.next_attempt_at);

    box.files.move_folder = nullptr;
    const rp::FlushReport later = box.outbox().flush(uploader, at(20));

    CHECK(uploader.runs == Lines{kId});
    CHECK(later.out == Lines{"moved run-0001 to failed"});
    CHECK(later.err.empty());
    CHECK(later.queued == 0);
    CHECK(later.failed == 1);
    CHECK(std::filesystem::exists(box.refused(kId) / "result.json"));
}

TEST_CASE("outbox flush: after a 401 a move to failed\ left by an earlier pass is still made",
          "[outbox][flush][w51]")
{
    // The W5.1 code review's finding 13: the move is a rename, sent nowhere.
    Box box;
    const path folder = box.queue_run("run-0002", 1);
    box.files.move_folder = [](const path&, const path&) { return 5ul; };
    FakeUploader uploader;
    uploader.answers = {failed("upload_http_409")};
    static_cast<void>(box.outbox().flush(uploader, at(10)));
    REQUIRE(box.manifest_of(folder).last_error == "upload_http_409");

    box.files.move_folder = nullptr;
    box.queue_run("run-0001", 0);
    uploader.answers = {failed("upload_http_401")};
    const rp::FlushReport report = box.outbox().flush(uploader, at(100));

    CHECK(uploader.runs == Lines{"run-0002", "run-0001"});
    CHECK(report.out == Lines{"kept run-0001: upload_http_401; attempt 1, next at " + text_at(160),
                              "moved run-0002 to failed"});
    CHECK(report.token_refused);
    CHECK(report.queued == 1);
    CHECK(report.failed == 1);
    CHECK(std::filesystem::exists(box.refused("run-0002") / "result.json"));
}

TEST_CASE("outbox flush: a 401 is kept by the schedule and stops the pass: no other run is sent "
          "with that token",
          "[outbox][flush][w51]")
{
    Box box;
    box.queue_run("run-0001", 0);
    box.queue_run("run-0002", 1);
    FakeUploader uploader;
    uploader.answers = {failed("upload_http_401")};

    const rp::FlushReport report = box.outbox().flush(uploader, at(100));

    CHECK(uploader.runs == Lines{"run-0001"});
    CHECK(report.out == Lines{"kept run-0001: upload_http_401; attempt 1, next at " + text_at(160)});
    CHECK(report.token_refused);
    CHECK(report.queued == 2);
    CHECK_FALSE(report.errors);
    CHECK_FALSE(box.manifest_of(box.queued("run-0002")).last_attempt_at);
}

TEST_CASE("outbox flush: told the token is new, a run kept by a 401 is tried at once", "[outbox][flush][w51]")
{
    Box box;
    box.queue_run("run-0001", 0);
    box.queue_run("run-0002", 1);
    FakeUploader uploader;
    uploader.answers = {failed("upload_http_401"), failed("upload_http_500")};
    static_cast<void>(box.outbox().flush(uploader, at(100)));
    REQUIRE(box.manifest_of(box.queued("run-0001")).next_attempt_at == text_at(160));

    // Not yet due: without the word the 401-kept run isn't tried.
    FakeUploader quiet;
    quiet.answers = {failed("upload_http_500")};
    const rp::FlushReport waiting = box.outbox().flush(quiet, at(110));
    CHECK(quiet.runs == Lines{"run-0002"});
    CHECK(waiting.out.front() == "waiting run-0001: next at " + text_at(160));

    // With it, the 401-kept run goes; the 500-kept one keeps its schedule.
    FakeUploader fresh;
    const rp::FlushReport sent = box.outbox().flush(fresh, at(111), {}, true);
    CHECK(fresh.runs == Lines{"run-0001"});
    CHECK(sent.out == Lines{"sent run-0001", "waiting run-0002: next at " + text_at(170)});
    CHECK_FALSE(sent.token_refused);
}

TEST_CASE("outbox holds: anything at failed\\<run_id> is failed, after outbox and sent", "[outbox][holds][w51]")
{
    Box box;
    std::filesystem::create_directories(box.refused(kId));

    CHECK(box.outbox().holds(kId) == rp::OutboxHolds::failed);
    std::filesystem::create_directories(box.sent(kId));
    CHECK(box.outbox().holds(kId) == rp::OutboxHolds::sent);
}

TEST_CASE("outbox queue and prepare: a run already failed is refused and its folder stays",
          "[outbox][queue][w51]")
{
    Box box;
    std::filesystem::create_directories(box.refused(kId));
    const path run = box.make_run(kId);

    const rp::QueueOutcome outcome = box.outbox().queue(run, kId, at(), true, "");

    CHECK(outcome.result == rp::QueueResult::already_failed);
    CHECK(box.outbox().queue_error(outcome, run) ==
          "outbox error: " + utf8_of(box.refused(kId)) + ": already failed");
    CHECK(std::filesystem::exists(run / "result.json"));
    CHECK(box.outbox().prepare(box.runs, kId) ==
          "outbox error: " + utf8_of(box.refused(kId)) + ": already failed; nothing was done");
}

TEST_CASE("outbox list: the runs under failed\\ are counted", "[outbox][list][w51]")
{
    Box box;
    std::filesystem::create_directories(box.refused("a"));
    std::filesystem::create_directories(box.refused("b"));

    const rp::OutboxListing listing = box.outbox().list();
    CHECK(listing.readable);
    CHECK(listing.failed == 2);
}

TEST_CASE("outbox flush: failed\\ counts under the cap and is never pruned", "[outbox][prune][w51]")
{
    Box box;
    box.queue_run("q");
    box.sent_run("s1", -100);
    std::filesystem::create_directories(box.refused("f"));
    std::map<std::string, std::uintmax_t> mb{{"q", 100}, {"s1", 100}, {"f", 450}};
    box.files.folder_bytes = [&](const path& folder) -> std::optional<std::uintmax_t> {
        return mb.at(utf8_of(folder.filename())) * 1024u * 1024u;
    };
    FakeUploader uploader;
    uploader.answers = {failed("upload_timeout")};

    const rp::FlushReport report = box.outbox().flush(uploader, at());

    CHECK(report.out == Lines{"pruned s1", "kept q: upload_timeout; attempt 1, next at " + text_at(60)});
    CHECK(report.err == Lines{"outbox warning: the outbox holds 550 MB, over the 500 MB cap"});
    CHECK(report.failed == 1);
    CHECK(std::filesystem::exists(box.refused("f")));
}

TEST_CASE("outbox flush: a refusal for good whose manifest can't be written still goes to failed\\",
          "[outbox][flush][w51]")
{
    Box box;
    box.queue_run(kId);
    int writes = 0;
    box.files.write_manifest = [&writes](const path&, std::string_view) {
        ++writes;
        return false;
    };
    FakeUploader uploader;
    uploader.answers = {failed("upload_http_409")};

    const rp::FlushReport report = box.outbox().flush(uploader, at(10));

    CHECK(writes == 1);
    CHECK(report.out == Lines{"failed run-0001: upload_http_409"});
    CHECK(report.err == Lines{"outbox error: " + utf8_of(box.queued(kId) / "manifest.json") + ": could not be written",
                              "outbox error: run-0001: refused by the Cloud (upload_http_409); moved to failed"});
    CHECK(std::filesystem::exists(box.refused(kId) / "result.json"));
}
