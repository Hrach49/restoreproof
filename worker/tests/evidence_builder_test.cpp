// W4.2 (docs/decisions.md 2026-10-05): the run folder, its two text files,
// the screenshot's seam and result.json, on a temp folder. The whole
// pipeline's evidence run is in test_command_test.cpp.

#include <rp/evidence_builder.hpp>

#include <rp/sha256.hpp>

#include "result_lab.hpp"
#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <spdlog/sinks/ostream_sink.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Catch::Matchers::ContainsSubstring;
using rp::Attachment;
using rp::Evidence;
using rp::EvidenceBuilder;
using rp::EvidenceError;
using rp::EvidenceFacts;
using rp::EvidenceFailure;
using rp::EvidenceOptions;
using rp::EvidenceText;
using rp::RunFolderCheck;
using rp::ScreenshotReason;
using rp::ScreenshotRequest;
using rp::test::ResultFacts;
using rp::test::TempDir;

const std::string kPng = std::string{"\x89PNG\r\n\x1a\n"} + "not really a picture";

std::optional<std::string> bytes_of(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    return std::string{std::istreambuf_iterator<char>(file), {}};
}

std::set<std::string> names_in(const std::filesystem::path& folder)
{
    std::set<std::string> names;
    for (const auto& entry : std::filesystem::directory_iterator(folder)) {
        names.insert(entry.path().filename().string());
    }
    return names;
}

EvidenceFacts facts_of(const ResultFacts& run)
{
    return {&run.expected, &run.restore, &run.check, &run.verdict};
}

// A run folder in a temp root, and a builder on it.
struct Lab {
    TempDir dir;
    std::filesystem::path folder;
    EvidenceOptions options;
    ResultFacts run = rp::test::full_result_facts();

    Lab()
    {
        REQUIRE(EvidenceBuilder::make_run_folder(dir.path() / "runs", "run-0001", folder) ==
                RunFolderCheck::ok);
        run.restore.log = "session s1 (mail): Success, 2 items processed (2 successes)\n"
                          "Success canary-mail-04: Item canary-mail-04 was restored successfully\n";
    }

    EvidenceBuilder builder() const { return EvidenceBuilder(folder, options); }

    // A capturer that writes `content` where it was asked to.
    static rp::ScreenshotCapturer writes(std::string content)
    {
        return [content](const ScreenshotRequest& request) -> std::optional<ScreenshotReason> {
            std::ofstream file(request.png, std::ios::binary);
            file << content;
            return std::nullopt;
        };
    }
};

std::vector<std::string> lines_of(const std::string& text)
{
    std::vector<std::string> lines;
    std::istringstream stream(text);
    for (std::string line; std::getline(stream, line);) {
        lines.push_back(line);
    }
    return lines;
}

} // namespace

TEST_CASE("a run ID that can't name a folder makes none", "[evidence]")
{
    const std::string run_id =
        GENERATE("a:b", ".", "..", "CON", "nul", "run.", "aux.txt", "COM1", "rp:20261003:a");
    CAPTURE(run_id);
    TempDir dir;
    std::filesystem::path folder;

    CHECK_FALSE(EvidenceBuilder::can_name_folder(run_id));
    CHECK(EvidenceBuilder::make_run_folder(dir.path(), run_id, folder) ==
          RunFolderCheck::not_a_folder_name);
    CHECK(folder.empty());
    CHECK(names_in(dir.path()).empty());
}

TEST_CASE("a run folder that is already there is never taken", "[evidence]")
{
    TempDir dir;
    std::filesystem::create_directory(dir.path() / "run-0001");
    dir.write("run-0001/items.csv", "an earlier run's");
    std::filesystem::path folder;

    SECTION("the same name")
    {
        CHECK(EvidenceBuilder::make_run_folder(dir.path(), "run-0001", folder) ==
              RunFolderCheck::exists);
    }
    SECTION("the same letters in another case")
    {
        CHECK(EvidenceBuilder::make_run_folder(dir.path(), "RUN-0001", folder) ==
              RunFolderCheck::exists);
    }
    SECTION("a file of that name")
    {
        dir.write("run-0002", "a file");
        CHECK(EvidenceBuilder::make_run_folder(dir.path(), "run-0002", folder) ==
              RunFolderCheck::exists);
    }
    CHECK(bytes_of(dir.path() / "run-0001" / "items.csv") == "an earlier run's");
    CHECK(names_in(dir.path() / "run-0001") == std::set<std::string>{"items.csv"});
}

TEST_CASE("a runs root that can't be made is no run folder", "[evidence]")
{
    TempDir dir;
    dir.write("runs", "a file where the root should be");
    std::filesystem::path folder;

    CHECK(EvidenceBuilder::make_run_folder(dir.path() / "runs", "run-0001", folder) ==
          RunFolderCheck::cannot_make);
}

TEST_CASE("the run folder is made under a root that isn't there yet", "[evidence]")
{
    TempDir dir;
    std::filesystem::path folder;

    CHECK(EvidenceBuilder::can_name_folder("rp-20260930T100000Z-0123abcd"));
    REQUIRE(EvidenceBuilder::make_run_folder(dir.path() / "a" / "runs",
                                             "rp-20260930T100000Z-0123abcd", folder) ==
            RunFolderCheck::ok);
    CHECK(folder == dir.path() / "a" / "runs" / "rp-20260930T100000Z-0123abcd");
    CHECK(std::filesystem::is_directory(folder));
    CHECK(names_in(folder).empty());
}

TEST_CASE("a text file that can't be written: no evidence, and the other is still tried",
          "[evidence]")
{
    const std::string refused = GENERATE("items.csv", "veeam-session.log");
    const bool throws = GENERATE(false, true);
    CAPTURE(refused, throws);
    Lab lab;
    int captures = 0;
    lab.options.screenshots_enabled = true;
    lab.options.capture = [&](const ScreenshotRequest&) -> std::optional<ScreenshotReason> {
        ++captures;
        return ScreenshotReason::timeout;
    };
    lab.options.write_file = [&](const std::filesystem::path& path, std::string_view content) {
        if (path.filename() == refused) {
            if (throws) {
                throw std::runtime_error("disk");
            }
            return false;
        }
        lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
        return true;
    };

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));

    CHECK_FALSE(written.evidence);
    REQUIRE(written.errors.size() == 1);
    CHECK(written.errors[0].file == refused);
    CHECK(written.errors[0].cause == EvidenceFailure::not_written);
    CHECK(captures == 0);
    const std::string other = refused == "items.csv" ? "veeam-session.log" : "items.csv";
    CHECK(names_in(lab.folder) == std::set<std::string>{other});
}

TEST_CASE("an attachment missing or changed after it was hashed: no result.json", "[evidence]")
{
    Lab lab;
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    const std::string csv = *bytes_of(lab.folder / "items.csv");
    std::string expected_file;

    SECTION("gone")
    {
        std::filesystem::remove(lab.folder / "veeam-session.log");
        expected_file = "veeam-session.log";
    }
    SECTION("longer")
    {
        std::ofstream(lab.folder / "items.csv", std::ios::binary | std::ios::app) << "9,\"x\"\n";
        expected_file = "items.csv";
    }
    SECTION("the same size, other bytes")
    {
        std::string edited = csv;
        edited.back() = 'X';
        std::ofstream(lab.folder / "items.csv", std::ios::binary | std::ios::trunc) << edited;
        expected_file = "items.csv";
    }

    const std::optional<EvidenceError> error = builder.write_result(*written.evidence, "{}");

    REQUIRE(error);
    CHECK(error->file == expected_file);
    CHECK(error->cause == EvidenceFailure::changed);
    CHECK_FALSE(std::filesystem::exists(lab.folder / "result.json"));
}

TEST_CASE("a result.json that can't be written says so", "[evidence]")
{
    const bool throws = GENERATE(false, true);
    Lab lab;
    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    lab.options.write_file = [&](const std::filesystem::path&, std::string_view) -> bool {
        if (throws) {
            throw std::runtime_error("disk");
        }
        return false;
    };

    const std::optional<EvidenceError> error =
        lab.builder().write_result(*written.evidence, "{}");

    REQUIRE(error);
    CHECK(error->file == "result.json");
    CHECK(error->cause == EvidenceFailure::not_written);
}

TEST_CASE("result.json is never written over one that is there", "[evidence]")
{
    Lab lab;
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    lab.dir.write("runs/run-0001/result.json", "another's");

    const std::optional<EvidenceError> error = builder.write_result(*written.evidence, "{}");

    REQUIRE(error);
    CHECK(error->cause == EvidenceFailure::not_written);
    CHECK(bytes_of(lab.folder / "result.json") == "another's");
}

TEST_CASE("screenshots off: the capturer isn't asked", "[evidence][screenshot]")
{
    Lab lab;
    int captures = 0;
    lab.options.capture = [&](const ScreenshotRequest&) -> std::optional<ScreenshotReason> {
        ++captures;
        return std::nullopt;
    };

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));

    REQUIRE(written.evidence);
    CHECK(captures == 0);
    CHECK_FALSE(written.evidence->screenshot.captured);
    CHECK(written.evidence->screenshot.reason == ScreenshotReason::disabled);
    CHECK(written.evidence->attachments.size() == 2);
}

TEST_CASE("screenshots on, the default capturer: no page, and no browser started",
          "[evidence][screenshot]")
{
    Lab lab;
    lab.options.screenshots_enabled = true;

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));

    REQUIRE(written.evidence);
    CHECK_FALSE(written.evidence->screenshot.captured);
    CHECK(written.evidence->screenshot.reason == ScreenshotReason::no_page);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
    CHECK(rp::no_screenshot_page({}) == ScreenshotReason::no_page);
}

TEST_CASE("a capturer's reason is the screenshot's, and what it left is removed",
          "[evidence][screenshot]")
{
    const ScreenshotReason reason =
        GENERATE(ScreenshotReason::timeout, ScreenshotReason::no_browser,
                 ScreenshotReason::login_required, ScreenshotReason::no_page,
                 ScreenshotReason::failed);
    Lab lab;
    lab.options.screenshots_enabled = true;
    std::optional<ScreenshotRequest> asked;
    lab.options.capture = [&](const ScreenshotRequest& request) -> std::optional<ScreenshotReason> {
        asked = request;
        std::ofstream(request.png, std::ios::binary) << "half a picture";
        return reason;
    };

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));

    REQUIRE(written.evidence);
    CHECK(written.errors.empty());
    CHECK_FALSE(written.evidence->screenshot.captured);
    CHECK(written.evidence->screenshot.reason == reason);
    CHECK(written.evidence->attachments.size() == 2);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
    REQUIRE(asked);
    CHECK(asked->png == lab.folder / "screenshot.png");
    CHECK(asked->session_ids == lab.run.restore.session_ids);
}

TEST_CASE("a capturer that fails is `failed`, never an error", "[evidence][screenshot]")
{
    Lab lab;
    lab.options.screenshots_enabled = true;

    SECTION("it throws")
    {
        lab.options.capture = [](const ScreenshotRequest&) -> std::optional<ScreenshotReason> {
            throw std::runtime_error("the browser crashed");
        };
    }
    SECTION("it says captured and left no file")
    {
        lab.options.capture = [](const ScreenshotRequest&) -> std::optional<ScreenshotReason> {
            return std::nullopt;
        };
    }
    SECTION("what it left isn't a PNG")
    {
        lab.options.capture = Lab::writes("<html>Sign in</html>");
    }
    SECTION("what it left is empty")
    {
        lab.options.capture = Lab::writes("");
    }
    SECTION("what it left is over the size allowed")
    {
        lab.options.capture = Lab::writes(
            kPng + std::string(static_cast<std::size_t>(rp::kMaxScreenshotBytes), 'x'));
    }

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));

    REQUIRE(written.evidence);
    CHECK(written.errors.empty());
    CHECK_FALSE(written.evidence->screenshot.captured);
    CHECK(written.evidence->screenshot.reason == ScreenshotReason::failed);
    CHECK(written.evidence->attachments.size() == 2);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
}

TEST_CASE("a secret value in a log line or an item's cell is withheld and said once",
          "[evidence][secrets]")
{
    Lab lab;
    lab.run.restore.log = "session s1 (mail): Success\n"
                          "Failed x: cannot sign in with SENTINEL_VEEAM_PW at the proxy\n"
                          "Success y: restored\n";
    lab.run.expected.items[1].mail->subject = "fwd: SENTINEL_PFX_PW";
    std::ostringstream log;
    lab.options.logger = std::make_shared<spdlog::logger>(
        "evidence", std::make_shared<spdlog::sinks::ostream_sink_mt>(log));
    lab.options.secrets = {"", "SENTINEL_VEEAM_PW", "SENTINEL_PFX_PW"};

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));

    REQUIRE(written.evidence);
    const std::string session_log = *bytes_of(lab.folder / "veeam-session.log");
    CHECK(session_log == "session s1 (mail): Success\n"
                         "[withheld: held a secret value]\n"
                         "Success y: restored\n");
    const std::vector<std::string> rows = lines_of(*bytes_of(lab.folder / "items.csv"));
    REQUIRE(rows.size() == 7);
    CHECK(rows[2] == "1,\"\",\"\",\"\",\"[withheld: held a secret value]\",\"\",\"\",\"\",\"\","
                     "\"\",\"\",\"\",\"\",\"\",\"\",");
    for (const std::string& file : {"veeam-session.log", "items.csv"}) {
        CHECK_THAT(*bytes_of(lab.folder / file), !ContainsSubstring("SENTINEL"));
    }
    CHECK_THAT(log.str(), ContainsSubstring("SECURITY: evidence: 2 line(s) held a secret value "
                                            "and were withheld"));
    CHECK_THAT(log.str(), !ContainsSubstring("SENTINEL"));
}

TEST_CASE("no secret, nothing withheld and nothing logged", "[evidence][secrets]")
{
    Lab lab;
    std::ostringstream log;
    lab.options.logger = std::make_shared<spdlog::logger>(
        "evidence", std::make_shared<spdlog::sinks::ostream_sink_mt>(log));
    lab.options.secrets = {"SENTINEL_VEEAM_PW", ""};

    REQUIRE(lab.builder().write_attachments(facts_of(lab.run)).evidence);

    CHECK(log.str().empty());
    CHECK(EvidenceBuilder::session_log(&lab.run.restore, {""}).withheld == 0);
}

TEST_CASE("items.csv: a name can't break its row or run as a formula", "[evidence][csv]")
{
    ResultFacts run = rp::test::full_result_facts();
    const auto name_cell = [&](const std::string& subject) {
        run.expected.items[1].mail->subject = subject;
        const std::vector<std::string> rows =
            lines_of(EvidenceBuilder::items_csv(facts_of(run)).text);
        REQUIRE(rows.size() == 7);
        const std::string start = "1,\"mail\",\"random\",\"\",";
        REQUIRE(rows[2].starts_with(start));
        return rows[2].substr(start.size(), rows[2].find(",\"fields\"") - start.size());
    };

    CHECK(name_cell("=HYPERLINK(\"http://x\")") == "\"'=HYPERLINK(\"\"http://x\"\")\"");
    CHECK(name_cell("+1") == "\"'+1\"");
    CHECK(name_cell("-1") == "\"'-1\"");
    CHECK(name_cell("@SUM(A1)") == "\"'@SUM(A1)\"");
    CHECK(name_cell("a, \"b\"") == "\"a, \"\"b\"\"\"");
    CHECK(name_cell("two\r\nlines\tand a tab") == "\"two  lines and a tab\"");
    CHECK(name_cell("Re: =1") == "\"Re: =1\"");
    CHECK(name_cell("") == "\"\"");
}

TEST_CASE("items.csv: one row per expected item, a found hash for a canary only",
          "[evidence][csv]")
{
    ResultFacts run = rp::test::full_result_facts();
    run.check.items[0].found_sha256 = std::string(64, 'c');
    run.check.items[2].found_sha256 = std::string(64, '9');
    run.check.items[2].outcome = rp::verification::CheckOutcome::mismatch;
    run.check.items[2].mismatches = {"size_bytes", "sha256"};
    run.verdict.failed = {2};
    run.verdict.verified_manifest -= 1;
    run.restore.items[5].outcome = rp::connector::ItemOutcome::failed;

    const EvidenceText csv = EvidenceBuilder::items_csv(facts_of(run));

    const std::string c(64, 'c');
    const std::string d(64, 'd');
    const std::string e(64, 'e');
    CHECK(csv.withheld == 0);
    CHECK(csv.text ==
          "index,type,source,canary_id,name,expected_kind,sha256_rule,expected_sha256,"
          "found_sha256,restore_outcome,found,outcome,mismatches,verdict,code,ms\n"
          "0,\"mail\",\"canary\",\"canary-mail-04\",\"canary-mail-04\",\"manifest\",\"text-v1\",\"" +
              c + "\",\"" + c + "\",\"restored\",\"yes\",\"match\",\"\",\"verified\",\"\",120\n"
          "1,\"mail\",\"random\",\"\",\"Quarterly figures\",\"fields\",\"\",\"\",\"\","
          "\"restored\",\"yes\",\"match\",\"\",\"verified\",\"\",121\n"
          "2,\"sharepoint\",\"canary\",\"canary-sp-04.docx\",\"canary-sp-04.docx\",\"manifest\","
          "\"office-v1\",\"" + d + "\",\"" + std::string(64, '9') +
              "\",\"restored\",\"yes\",\"mismatch\",\"size_bytes,sha256\",\"failed\",\"\",122\n"
          "3,\"sharepoint\",\"random\",\"\",\"Budget 2026.pdf\",\"metadata\",\"\",\"\",\"\","
          "\"restored\",\"yes\",\"match\",\"\",\"verified\",\"\",123\n"
          "4,\"onedrive\",\"canary\",\"canary-od-04.txt\",\"canary-od-04.txt\",\"manifest\","
          "\"bytes\",\"" + e + "\",\"\",\"restored\",\"yes\",\"match\",\"\",\"verified\",\"\",124\n"
          "5,\"onedrive\",\"random\",\"\",\"\xC3\x9C" "bersicht.docx\",\"metadata\",\"\",\"\",\"\","
          "\"failed\",\"yes\",\"match\",\"\",\"verified\",\"\",125\n");
}

TEST_CASE("items.csv: what a step that didn't run leaves empty", "[evidence][csv]")
{
    ResultFacts run = rp::test::full_result_facts();

    SECTION("no expected set: the header alone")
    {
        CHECK(EvidenceBuilder::items_csv({}).text ==
              "index,type,source,canary_id,name,expected_kind,sha256_rule,expected_sha256,"
              "found_sha256,restore_outcome,found,outcome,mismatches,verdict,code,ms\n");
    }
    SECTION("no restore, no check, no verdict")
    {
        const std::vector<std::string> rows =
            lines_of(EvidenceBuilder::items_csv({&run.expected, nullptr, nullptr, nullptr}).text);
        REQUIRE(rows.size() == 7);
        CHECK(rows[2] == "1,\"mail\",\"random\",\"\",\"Quarterly figures\",\"fields\",\"\",\"\","
                         "\"\",\"\",\"\",\"\",\"\",\"-\",\"\",");
    }
    SECTION("an unchecked item carries its code; one not found has no ms")
    {
        run.check.items[1].outcome = rp::verification::CheckOutcome::error;
        run.check.items[1].found = false;
        run.check.items[1].error_code = "graph_transient";
        run.verdict.unchecked = {{1, "graph_transient"}};
        run.verdict.verified_fields -= 1;
        const std::vector<std::string> rows =
            lines_of(EvidenceBuilder::items_csv(facts_of(run)).text);
        REQUIRE(rows.size() == 7);
        CHECK(rows[2] == "1,\"mail\",\"random\",\"\",\"Quarterly figures\",\"fields\",\"\",\"\","
                         "\"\",\"restored\",\"no\",\"error\",\"\",\"unchecked\","
                         "\"graph_transient\",");
    }
    SECTION("a run the item verdicts didn't decide: every verdict is -")
    {
        run.verdict.verified_manifest = 0;
        for (const std::string& line :
             lines_of(EvidenceBuilder::items_csv(facts_of(run)).text)) {
            if (!line.starts_with("index")) {
                CHECK_THAT(line, ContainsSubstring(",\"-\",\"\","));
            }
        }
    }
}

TEST_CASE("veeam-session.log is the connector's log, each line ended", "[evidence][log]")
{
    rp::connector::RestoreResult restore;

    CHECK(EvidenceBuilder::session_log(nullptr).text.empty());
    CHECK(EvidenceBuilder::session_log(&restore).text.empty());
    restore.log = "session s1 (mail): Success\nSuccess a: restored (source: Alice\\Inbox)\n";
    CHECK(EvidenceBuilder::session_log(&restore).text == restore.log);
    restore.log = "one\n\ntwo";
    CHECK(EvidenceBuilder::session_log(&restore).text == "one\n\ntwo\n");
}

TEST_CASE("the attachments are the folder's files, each with its hash and size",
          "[evidence][acceptance]")
{
    const bool screenshot = GENERATE(false, true);
    CAPTURE(screenshot);
    Lab lab;
    lab.options.screenshots_enabled = screenshot;
    lab.options.capture = Lab::writes(kPng);
    EvidenceBuilder builder = lab.builder();

    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));

    REQUIRE(written.evidence);
    CHECK(written.errors.empty());
    const Evidence& evidence = *written.evidence;
    std::vector<std::string> names;
    for (const Attachment& attachment : evidence.attachments) {
        names.push_back(attachment.name);
        const std::optional<std::string> bytes = bytes_of(lab.folder / attachment.name);
        REQUIRE(bytes);
        CHECK(attachment.sha256 == rp::sha256_hex(*bytes));
        CHECK(attachment.size_bytes == bytes->size());
    }
    CHECK(names == (screenshot ? std::vector<std::string>{"items.csv", "screenshot.png",
                                                          "veeam-session.log"}
                               : std::vector<std::string>{"items.csv", "veeam-session.log"}));
    CHECK(evidence.screenshot.captured == screenshot);
    CHECK(bytes_of(lab.folder / "veeam-session.log") == lab.run.restore.log);
    CHECK(bytes_of(lab.folder / "items.csv") ==
          EvidenceBuilder::items_csv(facts_of(lab.run)).text);
    if (screenshot) {
        CHECK(bytes_of(lab.folder / "screenshot.png") == kPng);
    }

    REQUIRE_FALSE(builder.write_result(evidence, "{\"format\":\"x\"}"));

    CHECK(bytes_of(lab.folder / "result.json") == "{\"format\":\"x\"}");
    std::set<std::string> all(names.begin(), names.end());
    all.insert("result.json");
    CHECK(names_in(lab.folder) == all);
    CHECK(builder.folder() == lab.folder);
}

TEST_CASE("the result's attachments and screenshot objects", "[evidence]")
{
    CHECK(rp::to_json(std::vector<Attachment>{}) == nlohmann::json::array());
    CHECK(rp::to_json(std::vector<Attachment>{{"items.csv", std::string(64, 'a'), 12}}) ==
          nlohmann::json::parse(R"([{"name":"items.csv","sha256":")" + std::string(64, 'a') +
                                R"(","size_bytes":12}])"));
    CHECK(rp::to_json(rp::Screenshot{true, ScreenshotReason::failed}) ==
          nlohmann::json{{"state", "captured"}});
    CHECK(rp::to_json(rp::Screenshot{false, ScreenshotReason::no_page}) ==
          nlohmann::json{{"state", "unavailable"}, {"reason", "no_page"}});
    CHECK(rp::screenshot_reasons() ==
          std::vector<std::string>{"disabled", "no_page", "no_browser", "login_required",
                                   "timeout", "failed"});
    CHECK(rp::attachment_names() ==
          std::vector<std::string>{"items.csv", "screenshot.png", "veeam-session.log"});
    CHECK(rp::to_string(static_cast<ScreenshotReason>(99)) == "unknown");
}

// After the code review of 2026-10-05.

TEST_CASE("a run folder too deep for the writer's own temp name is not made, and not left",
          "[evidence]")
{
    TempDir dir;
    const std::string run_id(20, 'r');
    // The folder itself can be made (under 248 characters); the longest file
    // in it with the writer's 21-character temp suffix can't (over 259).
    std::filesystem::path root = dir.path();
    while ((root / run_id).native().size() < 215) {
        root /= std::string(std::min<std::size_t>(40, 229 - (root / run_id).native().size()), 'd');
    }
    REQUIRE((root / run_id).native().size() >= 215);
    REQUIRE((root / run_id).native().size() < 240);
    std::filesystem::path folder;

    CHECK(EvidenceBuilder::make_run_folder(root, run_id, folder) == RunFolderCheck::cannot_make);
    CHECK_FALSE(std::filesystem::exists(root / run_id));
}

TEST_CASE("a capturer's answer the result has no word for is `failed`", "[evidence][screenshot]")
{
    const ScreenshotReason answer =
        GENERATE(ScreenshotReason::disabled, static_cast<ScreenshotReason>(99));
    Lab lab;
    lab.options.screenshots_enabled = true;
    lab.options.capture = [&](const ScreenshotRequest&) -> std::optional<ScreenshotReason> {
        return answer;
    };

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));

    REQUIRE(written.evidence);
    CHECK(written.evidence->screenshot.reason == ScreenshotReason::failed);
}

TEST_CASE("a folder a capturer left where the PNG should be is removed with what it holds",
          "[evidence][screenshot]")
{
    Lab lab;
    lab.options.screenshots_enabled = true;
    lab.options.capture = [](const ScreenshotRequest& request) -> std::optional<ScreenshotReason> {
        std::filesystem::create_directory(request.png);
        std::ofstream(request.png / "profile.dat", std::ios::binary) << "a browser's";
        return std::nullopt;
    };

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));

    REQUIRE(written.evidence);
    CHECK(written.evidence->screenshot.reason == ScreenshotReason::failed);
    CHECK_FALSE(written.evidence->screenshot.captured);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
}

TEST_CASE("a PNG of exactly the size allowed is an attachment", "[evidence][screenshot]")
{
    Lab lab;
    lab.options.screenshots_enabled = true;
    const std::string png =
        kPng + std::string(static_cast<std::size_t>(rp::kMaxScreenshotBytes) - kPng.size(), 'x');
    lab.options.capture = Lab::writes(png);

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));

    REQUIRE(written.evidence);
    CHECK(written.evidence->screenshot.captured);
    REQUIRE(written.evidence->attachments.size() == 3);
    CHECK(written.evidence->attachments[1].size_bytes == rp::kMaxScreenshotBytes);
}

TEST_CASE("without a result to list it, no screenshot is asked for", "[evidence][screenshot]")
{
    Lab lab;
    int captures = 0;
    lab.options.screenshots_enabled = true;
    lab.options.capture = [&](const ScreenshotRequest&) -> std::optional<ScreenshotReason> {
        ++captures;
        return std::nullopt;
    };

    const EvidenceBuilder::Written written =
        lab.builder().write_attachments(facts_of(lab.run), false);

    REQUIRE(written.evidence);
    CHECK(captures == 0);
    CHECK(written.evidence->attachments.size() == 2);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
}

TEST_CASE("items.csv: a secret that a control character spells once written is withheld too",
          "[evidence][secrets][csv]")
{
    ResultFacts run = rp::test::full_result_facts();
    run.expected.items[1].mail->subject = "my\tpass";

    const EvidenceText csv = EvidenceBuilder::items_csv(facts_of(run), {"my pass"});

    CHECK(csv.withheld == 1);
    CHECK_THAT(csv.text, !ContainsSubstring("my pass"));
}

TEST_CASE("the attachments' names are in order and each is there once", "[evidence]")
{
    Lab lab;
    lab.options.screenshots_enabled = true;
    lab.options.capture = Lab::writes(kPng);

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));

    REQUIRE(written.evidence);
    std::vector<std::string> names;
    for (const Attachment& attachment : written.evidence->attachments) {
        names.push_back(attachment.name);
    }
    CHECK(names == rp::attachment_names());
    CHECK(std::set<std::string>(names.begin(), names.end()).size() == names.size());
}
