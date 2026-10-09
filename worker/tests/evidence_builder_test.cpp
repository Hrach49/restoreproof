// W4.2 (docs/decisions.md 2026-10-05): the run folder, its two text files,
// the screenshot's seam and result.json, on a temp folder; W4.3: the
// signature beside it, signature.json, written just before result.json. The
// whole pipeline's evidence run is in test_command_test.cpp. The only key
// here is RFC 8032's published test key 1.

#include <rp/evidence_builder.hpp>

#include <rp/canonical_json.hpp>
#include <rp/sha256.hpp>
#include <rp/signer.hpp>
#include <rp/timestamper.hpp>

#include "../src/file_read.hpp"

#include "result_lab.hpp"
#include "signing_lab.hpp"
#include "test_support.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <spdlog/sinks/ostream_sink.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
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
using rp::RunFolder;
using rp::RunFolderCheck;
using rp::ScreenshotReason;
using rp::ScreenshotRequest;
using rp::SignedResult;
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

// The real Signer with `key`, as the pipeline hands it to the builder.
rp::ResultSigner signer_with(std::shared_ptr<rp::SigningKey> key)
{
    return [key](std::string_view canonical) { return rp::Signer::sign(canonical, *key); };
}

// A run folder in a temp root, and a builder on it that signs with test key 1.
struct Lab {
    TempDir dir;
    std::filesystem::path folder;
    EvidenceOptions options;
    ResultFacts run = rp::test::full_result_facts();
    std::shared_ptr<rp::SigningKey> key =
        std::make_shared<rp::SigningKey>(rp::test::signing_key());

    Lab()
    {
        options.sign = signer_with(key);
        RunFolder made;
        REQUIRE(EvidenceBuilder::make_run_folder(dir.path() / "runs", "run-0001", made) ==
                RunFolderCheck::ok);
        made.keep();
        folder = made.path();
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
    RunFolder folder;

    CHECK_FALSE(EvidenceBuilder::can_name_folder(run_id));
    CHECK(EvidenceBuilder::make_run_folder(dir.path(), run_id, folder) ==
          RunFolderCheck::not_a_folder_name);
    CHECK(folder.path().empty());
    CHECK(names_in(dir.path()).empty());
}

TEST_CASE("a run folder that is already there is never taken", "[evidence]")
{
    TempDir dir;
    std::filesystem::create_directory(dir.path() / "run-0001");
    dir.write("run-0001/items.csv", "an earlier run's");
    RunFolder folder;

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
    RunFolder folder;

    CHECK(EvidenceBuilder::make_run_folder(dir.path() / "runs", "run-0001", folder) ==
          RunFolderCheck::cannot_make);
    CHECK(folder.path() == dir.path() / "runs" / "run-0001");
    CHECK(bytes_of(dir.path() / "runs") == "a file where the root should be");
}

TEST_CASE("the run folder is made under a root that isn't there yet", "[evidence]")
{
    TempDir dir;
    RunFolder folder;

    CHECK(EvidenceBuilder::can_name_folder("rp-20260930T100000Z-0123abcd"));
    REQUIRE(EvidenceBuilder::make_run_folder(dir.path() / "a" / "runs",
                                             "rp-20260930T100000Z-0123abcd", folder) ==
            RunFolderCheck::ok);
    CHECK(folder.path() == dir.path() / "a" / "runs" / "rp-20260930T100000Z-0123abcd");
    CHECK(std::filesystem::is_directory(folder.path()));
    CHECK(names_in(folder.path()).empty());
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

TEST_CASE("a signature.json that can't be written says so, and result.json isn't tried",
          "[evidence][signing]")
{
    const bool throws = GENERATE(false, true);
    Lab lab;
    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    std::vector<std::string> asked;
    lab.options.write_file = [&](const std::filesystem::path& path, std::string_view) -> bool {
        asked.push_back(path.filename().string());
        if (throws) {
            throw std::runtime_error("disk");
        }
        return false;
    };
    SignedResult signature;

    const std::optional<EvidenceError> error =
        lab.builder().write_result(*written.evidence, "{}", &signature);

    REQUIRE(error);
    CHECK(error->file == "signature.json");
    CHECK(error->cause == EvidenceFailure::not_written);
    CHECK(asked == std::vector<std::string>{"signature.json"});
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
    CHECK(signature.bundle_sha256.empty());
}

TEST_CASE("a result.json that can't be written after signature.json was: the signature is "
          "removed again",
          "[evidence][signing]")
{
    const bool throws = GENERATE(false, true);
    Lab lab;
    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    std::vector<std::string> asked;
    bool signature_was_there = false;
    lab.options.write_file = [&](const std::filesystem::path& path, std::string_view content) {
        asked.push_back(path.filename().string());
        if (path.filename() == "result.json") {
            signature_was_there = std::filesystem::exists(lab.folder / "signature.json");
            if (throws) {
                throw std::runtime_error("disk");
            }
            return false;
        }
        lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
        return true;
    };
    SignedResult signature;

    const std::optional<EvidenceError> error =
        lab.builder().write_result(*written.evidence, "{}", &signature);

    REQUIRE(error);
    CHECK(error->file == "result.json");
    CHECK(error->cause == EvidenceFailure::not_written);
    CHECK(asked == std::vector<std::string>{"signature.json", "result.json"});
    CHECK(signature_was_there);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
    CHECK(signature.bundle_sha256.empty());
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
    CHECK(error->file == "result.json");
    CHECK(error->cause == EvidenceFailure::not_written);
    CHECK(bytes_of(lab.folder / "result.json") == "another's");
    // Nor does this run's signature stay beside another's result.
    CHECK_FALSE(std::filesystem::exists(lab.folder / "signature.json"));
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
    // The signature is in the folder and never among the attachments.
    std::set<std::string> all(names.begin(), names.end());
    all.insert("result.json");
    all.insert("signature.json");
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
    // A folder of exactly 230 characters, whatever the temp folder's own
    // length: it can be made (under 248), and "\veeam-session.log" with the
    // writer's temp suffix, 39 more, can't (over 259).
    constexpr std::size_t kFolderLength = 230;
    std::filesystem::path root = dir.path();
    for (std::size_t length = (root / run_id).native().size(); length != kFolderLength;
         length = (root / run_id).native().size()) {
        // Each level adds its separator too; never one that leaves a single
        // character to go.
        REQUIRE(length + 2 <= kFolderLength);
        const std::size_t left = kFolderLength - length;
        root /= std::string(left <= 42 ? left - 1 : 40, 'd');
    }
    RunFolder folder;

    CHECK(EvidenceBuilder::make_run_folder(root, run_id, folder) == RunFolderCheck::cannot_make);
    CHECK_FALSE(std::filesystem::exists(root / run_id));
    // Nor the levels of the root made on the way: nothing was done.
    CHECK(names_in(dir.path()).empty());
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

// After the code review of PR #157 (docs/decisions.md 2026-10-05, "W4.2 code
// review").

TEST_CASE("a run with no restore session has no page: the capturer isn't asked",
          "[evidence][screenshot]")
{
    Lab lab;
    int captures = 0;
    lab.options.screenshots_enabled = true;
    lab.options.capture = [&](const ScreenshotRequest& request) -> std::optional<ScreenshotReason> {
        ++captures;
        std::ofstream(request.png, std::ios::binary) << kPng;
        return std::nullopt;
    };
    EvidenceFacts facts = facts_of(lab.run);

    SECTION("no restore result")
    {
        facts.restore = nullptr;
    }
    SECTION("a restore result without a session")
    {
        lab.run.restore.session_ids.clear();
    }

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts);

    REQUIRE(written.evidence);
    CHECK(captures == 0);
    CHECK_FALSE(written.evidence->screenshot.captured);
    CHECK(written.evidence->screenshot.reason == ScreenshotReason::no_page);
    CHECK(written.evidence->attachments.size() == 2);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
}

TEST_CASE("a screenshot that can't be read whole is `failed`, never a shorter picture",
          "[evidence][screenshot]")
{
    Lab lab;
    lab.options.screenshots_enabled = true;
    // The capturer leaves a PNG whose second half another handle holds
    // locked: its size is known, and a read of it stops short.
    constexpr DWORD kHalf = 32 * 1024;
    const std::string png = kPng + std::string(2 * kHalf - kPng.size(), 'x');
    HANDLE holder = INVALID_HANDLE_VALUE;
    bool locked = false;
    lab.options.capture = [&](const ScreenshotRequest& request) -> std::optional<ScreenshotReason> {
        std::ofstream(request.png, std::ios::binary) << png;
        holder = CreateFileW(request.png.c_str(), GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (holder != INVALID_HANDLE_VALUE) {
            OVERLAPPED from{};
            from.Offset = kHalf;
            locked = LockFileEx(holder, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
                                kHalf, 0, &from) != 0;
        }
        return std::nullopt;
    };

    const EvidenceBuilder::Written written = lab.builder().write_attachments(facts_of(lab.run));

    if (holder != INVALID_HANDLE_VALUE) {
        CloseHandle(holder);
    }
    REQUIRE(locked);
    REQUIRE(written.evidence);
    CHECK_FALSE(written.evidence->screenshot.captured);
    CHECK(written.evidence->screenshot.reason == ScreenshotReason::failed);
    CHECK(written.evidence->attachments.size() == 2);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
}

TEST_CASE("a run folder that isn't kept is taken away again, with the root made for it",
          "[evidence]")
{
    TempDir dir;
    const std::filesystem::path root = dir.path() / "a" / "runs";

    SECTION("dropped as it goes: the folder and every level made for it")
    {
        {
            RunFolder folder;
            REQUIRE(EvidenceBuilder::make_run_folder(root, "run-0001", folder) ==
                    RunFolderCheck::ok);
            CHECK(std::filesystem::is_directory(root / "run-0001"));
        }
        CHECK(names_in(dir.path()).empty());
    }
    SECTION("kept: it stays")
    {
        {
            RunFolder folder;
            REQUIRE(EvidenceBuilder::make_run_folder(root, "run-0001", folder) ==
                    RunFolderCheck::ok);
            folder.keep();
            folder.drop();
            CHECK(folder.path() == root / "run-0001");
        }
        CHECK(std::filesystem::is_directory(root / "run-0001"));
    }
    SECTION("a level that was there before stays")
    {
        std::filesystem::create_directory(dir.path() / "a");
        {
            RunFolder folder;
            REQUIRE(EvidenceBuilder::make_run_folder(root, "run-0001", folder) ==
                    RunFolderCheck::ok);
        }
        CHECK(names_in(dir.path()) == std::set<std::string>{"a"});
        CHECK(names_in(dir.path() / "a").empty());
    }
    SECTION("only what is empty goes: a level another run wrote into stays")
    {
        {
            RunFolder folder;
            REQUIRE(EvidenceBuilder::make_run_folder(root, "run-0001", folder) ==
                    RunFolderCheck::ok);
            std::filesystem::create_directory(root / "run-0002");
        }
        CHECK(names_in(root) == std::set<std::string>{"run-0002"});
    }
    SECTION("a folder that was there is another run's, and its root's levels were not made")
    {
        std::filesystem::create_directories(root / "run-0001");
        {
            RunFolder folder;
            REQUIRE(EvidenceBuilder::make_run_folder(root, "run-0001", folder) ==
                    RunFolderCheck::exists);
        }
        CHECK(std::filesystem::is_directory(root / "run-0001"));
    }
    SECTION("none made: nothing to drop")
    {
        RunFolder folder;
        folder.drop();
        CHECK(folder.path().empty());
        CHECK(names_in(dir.path()).empty());
    }
}

TEST_CASE("a result that holds a secret value is never written, and said once",
          "[evidence][secrets]")
{
    Lab lab;
    std::ostringstream log;
    lab.options.logger = std::make_shared<spdlog::logger>(
        "evidence", std::make_shared<spdlog::sinks::ostream_sink_mt>(log));
    // As JSON writes it the secret's quotes are escaped: its text alone
    // wouldn't show it.
    lab.options.secrets = {"", "SENTINEL \"VEEAM\" PW"};
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    nlohmann::json result;
    result["format"] = "restoreproof.result.v1";
    result["expected"]["items"][0]["subject"] = "Quarterly figures";
    result["expected"]["items"][1]["subject"] = "fwd: SENTINEL \"VEEAM\" PW";
    REQUIRE(result.dump().find("SENTINEL \"VEEAM\" PW") == std::string::npos);

    const std::optional<EvidenceError> error = builder.write_result(*written.evidence, result.dump());

    REQUIRE(error);
    CHECK(error->file == "result.json");
    CHECK(error->cause == EvidenceFailure::holds_secret);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
    CHECK_THAT(log.str(), ContainsSubstring("SECURITY: evidence: the result held a secret value; "
                                            "no result.json was written"));
    CHECK_THAT(log.str(), !ContainsSubstring("SENTINEL"));
}

TEST_CASE("a result that holds no secret value is written as it is", "[evidence][secrets]")
{
    Lab lab;
    std::ostringstream log;
    lab.options.logger = std::make_shared<spdlog::logger>(
        "evidence", std::make_shared<spdlog::sinks::ostream_sink_mt>(log));
    lab.options.secrets = {"", "SENTINEL_VEEAM_PW"};
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    // A key or a number is never tenant text: only the strings are looked at.
    const std::string canonical =
        R"({"count":3,"items":[{"subject":"Quarterly figures"},null,true],"status":"pass"})";

    REQUIRE_FALSE(builder.write_result(*written.evidence, canonical));

    CHECK(bytes_of(lab.folder / "result.json") == canonical);
    CHECK(log.str().empty());
}

// --- W4.3: the signature (docs/decisions.md 2026-10-05, points 2 to 4) -------------------

TEST_CASE("a result that can't be signed: the attachments stay, no signature.json, no "
          "result.json",
          "[evidence][signing]")
{
    using rp::test::Ed25519Fault;
    using rp::test::FakeEd25519;
    Lab lab;
    FakeEd25519 primitive;
    std::vector<std::string> written_names;
    lab.options.write_file = [&](const std::filesystem::path& path, std::string_view content) {
        written_names.push_back(path.filename().string());
        lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
        return true;
    };

    SECTION("no signer")
    {
        lab.options.sign = nullptr;
    }
    SECTION("the signer answers nothing")
    {
        lab.options.sign = [](std::string_view) -> std::optional<SignedResult> {
            return std::nullopt;
        };
    }
    SECTION("the signer throws")
    {
        lab.options.sign = [](std::string_view) -> std::optional<SignedResult> {
            throw std::runtime_error("the key store");
        };
    }
    SECTION("the primitive fails at one of its calls")
    {
        const Ed25519Fault fault =
            GENERATE(Ed25519Fault::sign_none, Ed25519Fault::sign_throws, Ed25519Fault::sign_other,
                     Ed25519Fault::check_false, Ed25519Fault::check_throws);
        CAPTURE(static_cast<int>(fault));
        lab.options.sign = signer_with(std::make_shared<rp::SigningKey>(
            rp::test::signing_key(rp::test::kSigningKey1Base64, primitive)));
        primitive.fault = fault;
    }

    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    written_names.clear();
    SignedResult signature;

    const std::optional<EvidenceError> error =
        builder.write_result(*written.evidence, "{\"format\":\"x\"}", &signature);

    REQUIRE(error);
    CHECK(error->file == "result.json");
    CHECK(error->cause == EvidenceFailure::not_signed);
    CHECK(written_names.empty());
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
    CHECK(signature.signature_file.empty());
}

TEST_CASE("the result is signed as it is written: signature.json, then result.json, and the "
          "folder verifies under the key's public half",
          "[evidence][signing][acceptance]")
{
    Lab lab;
    std::vector<std::string> order;
    std::vector<std::string> signed_texts;
    lab.options.sign = [&, real = signer_with(lab.key)](std::string_view canonical) {
        // Asked once the attachments are written, before either JSON file.
        order.push_back("sign");
        signed_texts.emplace_back(canonical);
        return real(canonical);
    };
    lab.options.write_file = [&](const std::filesystem::path& path, std::string_view content) {
        order.push_back(path.filename().string());
        lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
        return true;
    };
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    // A whole valid result that lists the folder's two attachments.
    nlohmann::json document = nlohmann::json::parse(
        rp::test::read_shared("testdata/result-v1/valid.json"));
    document["attachments"] = rp::to_json(written.evidence->attachments);
    const std::string canonical = rp::canonical_json(document);
    SignedResult signature;

    REQUIRE_FALSE(builder.write_result(*written.evidence, canonical, &signature));

    CHECK(order == std::vector<std::string>{"items.csv", "veeam-session.log", "sign",
                                            "signature.json", "result.json"});
    CHECK(signed_texts == std::vector<std::string>{canonical});
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "result.json",
                                                        "signature.json", "veeam-session.log"});
    CHECK(bytes_of(lab.folder / "result.json") == canonical);
    CHECK(bytes_of(lab.folder / "signature.json") == signature.signature_file);
    CHECK(signature.bundle_sha256 == rp::sha256_hex(canonical));
    CHECK(signature.key_id == lab.key->key_id());
    // The attachments never list the signature, which depends on the result's hash.
    CHECK_THAT(canonical, !ContainsSubstring("signature.json"));

    const rp::PublicKey public_key = rp::test::public_key_of(*lab.key);
    const rp::Verification verified = rp::Signer::verify_folder(
        rp::folder_reader(lab.folder), *rp::list_folder(lab.folder), public_key);
    CHECK(rp::to_string(verified.word) == "verified");
    CHECK(verified.bundle_sha256 == signature.bundle_sha256);
    CHECK(verified.key_id == signature.key_id);
    CHECK(verified.notes.empty());

    // One byte of an attachment changed afterwards, and it no longer does.
    std::string csv = *bytes_of(lab.folder / "items.csv");
    csv.back() = 'X';
    std::ofstream(lab.folder / "items.csv", std::ios::binary | std::ios::trunc) << csv;
    CHECK(rp::to_string(rp::Signer::verify_folder(rp::folder_reader(lab.folder),
                                                  *rp::list_folder(lab.folder), public_key)
                            .word) == "attachment_hash");
}

TEST_CASE("nothing is signed that won't be written: a secret in the result, an attachment "
          "that changed",
          "[evidence][signing]")
{
    Lab lab;
    int signs = 0;
    lab.options.sign = [&, real = signer_with(lab.key)](std::string_view canonical) {
        ++signs;
        return real(canonical);
    };
    lab.options.secrets = {"SENTINEL_VEEAM_PW"};
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    std::optional<EvidenceError> error;

    SECTION("the result holds a secret value")
    {
        error = builder.write_result(*written.evidence, R"({"subject":"SENTINEL_VEEAM_PW"})");

        REQUIRE(error);
        CHECK(error->cause == EvidenceFailure::holds_secret);
    }
    SECTION("an attachment is gone")
    {
        std::filesystem::remove(lab.folder / "items.csv");

        error = builder.write_result(*written.evidence, "{}");

        REQUIRE(error);
        CHECK(error->cause == EvidenceFailure::changed);
    }
    CHECK(signs == 0);
    CHECK_FALSE(std::filesystem::exists(lab.folder / "signature.json"));
    CHECK_FALSE(std::filesystem::exists(lab.folder / "result.json"));
}

TEST_CASE("the signature's name is not an attachment's, and is shorter than the longest name "
          "the run folder is probed with",
          "[evidence][signing]")
{
    const std::vector<std::string>& names = rp::attachment_names();
    CHECK(std::ranges::find(names, std::string{rp::kSignatureFileName}) == names.end());
    CHECK(rp::kSignatureFileName.size() < rp::kSessionLogName.size());
}

TEST_CASE("the real Signer signs only text that is its own canonical form", "[evidence][signing]")
{
    Lab lab;
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);

    const std::optional<EvidenceError> error =
        builder.write_result(*written.evidence, "{\"b\":1,\"a\":2}");

    REQUIRE(error);
    CHECK(error->file == "result.json");
    CHECK(error->cause == EvidenceFailure::not_signed);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
}

// --- W4.4: the timestamp ---------------------------------------------------------

namespace {

const std::string kToken = std::string("\x30\x82\x01\x00", 4) + "a token's bytes" + "\xff";

rp::TimestampOutcome stamped(std::string token = kToken)
{
    rp::TimestampOutcome outcome;
    outcome.token = std::move(token);
    outcome.gen_time = 1791288000;
    outcome.attempts = 1;
    return outcome;
}

rp::TimestampOutcome not_stamped(std::string_view code)
{
    rp::TimestampOutcome outcome;
    outcome.error = code;
    outcome.attempts = 3;
    return outcome;
}

const std::set<std::string> kSignedFiles = {"items.csv", "result.json", "signature.json",
                                            "veeam-session.log"};

// A lab whose writer writes and records, and whose timestamper is `answer`.
struct StampLab : Lab {
    std::vector<std::string> order;
    std::vector<std::vector<unsigned char>> asked;

    explicit StampLab(std::function<rp::TimestampOutcome()> answer)
    {
        options.sign = [this, real = signer_with(key)](std::string_view canonical) {
            order.push_back("sign");
            return real(canonical);
        };
        options.timestamp = [this, answer](std::span<const unsigned char, 32> digest) {
            order.push_back("timestamp");
            asked.emplace_back(digest.begin(), digest.end());
            return answer();
        };
        options.write_file = [this](const std::filesystem::path& path, std::string_view content) {
            order.push_back(path.filename().string());
            dir.write(std::filesystem::relative(path, dir.path()), content);
            return true;
        };
    }
};

} // namespace

TEST_CASE("the TSA gave no token: the folder is complete without one, and the code is handed on",
          "[evidence][timestamp]")
{
    const std::string_view code = GENERATE(rp::timestamp_code::kUnreachable,
                                           rp::timestamp_code::kUntrusted,
                                           rp::timestamp_code::kRejected);
    StampLab lab([code] { return not_stamped(code); });
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    SignedResult signature;
    rp::TimestampOutcome timestamp;

    REQUIRE_FALSE(builder.write_result(*written.evidence, "{}", &signature, &timestamp));

    CHECK(lab.order == std::vector<std::string>{"items.csv", "veeam-session.log", "sign",
                                                "timestamp", "signature.json", "result.json"});
    CHECK(names_in(lab.folder) == kSignedFiles);
    CHECK_FALSE(timestamp.stamped());
    CHECK(timestamp.error == code);
    CHECK(timestamp.attempts == 3);
    CHECK(signature.bundle_sha256 == rp::sha256_hex("{}"));
}

TEST_CASE("a timestamper that throws or answers nothing is timestamp_internal, and the folder "
          "is still complete",
          "[evidence][timestamp]")
{
    const bool throws = GENERATE(false, true);
    StampLab lab([throws]() -> rp::TimestampOutcome {
        if (throws) {
            throw std::runtime_error("tsa");
        }
        return {};
    });
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    rp::TimestampOutcome timestamp = stamped();

    REQUIRE_FALSE(builder.write_result(*written.evidence, "{}", nullptr, &timestamp));

    CHECK(names_in(lab.folder) == kSignedFiles);
    CHECK_FALSE(timestamp.stamped());
    CHECK(timestamp.error == rp::timestamp_code::kInternal);
}

TEST_CASE("a token that can't be written is timestamp_not_written; result.json is still "
          "written",
          "[evidence][timestamp]")
{
    const bool throws = GENERATE(false, true);
    StampLab lab([] { return stamped(); });
    lab.options.write_file = [&](const std::filesystem::path& path, std::string_view content) {
        lab.order.push_back(path.filename().string());
        if (path.filename() == "timestamp.tst") {
            if (throws) {
                throw std::runtime_error("disk");
            }
            return false;
        }
        lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
        return true;
    };
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    rp::TimestampOutcome timestamp;

    REQUIRE_FALSE(builder.write_result(*written.evidence, "{}", nullptr, &timestamp));

    CHECK(lab.order == std::vector<std::string>{"items.csv", "veeam-session.log", "sign",
                                                "timestamp", "signature.json", "timestamp.tst",
                                                "result.json"});
    CHECK(names_in(lab.folder) == kSignedFiles);
    CHECK_FALSE(timestamp.stamped());
    CHECK(timestamp.token.empty());
    CHECK(timestamp.gen_time == 0);
    CHECK(timestamp.error == rp::timestamp_code::kNotWritten);
    CHECK(timestamp.attempts == 1);
}

TEST_CASE("a token over the size allowed is never handed to the writer", "[evidence][timestamp]")
{
    StampLab lab([] { return stamped(std::string(rp::kMaxTimestampFileBytes + 1, 'T')); });
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    rp::TimestampOutcome timestamp;

    REQUIRE_FALSE(builder.write_result(*written.evidence, "{}", nullptr, &timestamp));

    CHECK(names_in(lab.folder) == kSignedFiles);
    CHECK(std::ranges::find(lab.order, "timestamp.tst") == lab.order.end());
    CHECK(timestamp.error == rp::timestamp_code::kNotWritten);
}

TEST_CASE("a result.json that can't be written after the token was: neither the token nor the "
          "signature stays",
          "[evidence][timestamp]")
{
    StampLab lab([] { return stamped(); });
    bool both_were_there = false;
    lab.options.write_file = [&](const std::filesystem::path& path, std::string_view content) {
        lab.order.push_back(path.filename().string());
        if (path.filename() == "result.json") {
            both_were_there = std::filesystem::exists(lab.folder / "signature.json") &&
                              std::filesystem::exists(lab.folder / "timestamp.tst");
            return false;
        }
        lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
        return true;
    };
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    SignedResult signature;
    rp::TimestampOutcome timestamp;

    const std::optional<EvidenceError> error =
        builder.write_result(*written.evidence, "{}", &signature, &timestamp);

    REQUIRE(error);
    CHECK(error->file == "result.json");
    CHECK(error->cause == EvidenceFailure::not_written);
    CHECK(both_were_there);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
    // Nothing is handed on for a folder that isn't complete.
    CHECK(signature.bundle_sha256.empty());
    CHECK_FALSE(timestamp.stamped());
    CHECK(timestamp.attempts == 0);
}

TEST_CASE("a signature.json that can't be written: the token isn't written either",
          "[evidence][timestamp]")
{
    StampLab lab([] { return stamped(); });
    lab.options.write_file = [&](const std::filesystem::path& path, std::string_view) {
        lab.order.push_back(path.filename().string());
        return false;
    };
    EvidenceBuilder builder = lab.builder();
    Evidence evidence;
    rp::TimestampOutcome timestamp;

    const std::optional<EvidenceError> error =
        builder.write_result(evidence, "{}", nullptr, &timestamp);

    REQUIRE(error);
    CHECK(error->file == "signature.json");
    CHECK(lab.order == std::vector<std::string>{"sign", "timestamp", "signature.json"});
    CHECK(names_in(lab.folder).empty());
    CHECK(timestamp.attempts == 0);
}

TEST_CASE("the TSA is never asked about a result that won't be written", "[evidence][timestamp]")
{
    StampLab lab([] { return stamped(); });
    Evidence evidence;
    std::string canonical = "{}";
    SECTION("it can't be signed")
    {
        lab.options.sign = [](std::string_view) -> std::optional<SignedResult> {
            return std::nullopt;
        };
    }
    SECTION("it holds a secret value")
    {
        lab.options.secrets = {"SENTINEL-SECRET"};
        canonical = R"({"note":"SENTINEL-SECRET"})";
    }
    SECTION("an attachment is gone")
    {
        evidence.attachments.push_back({"items.csv", std::string(64, '0'), 1});
    }

    REQUIRE(lab.builder().write_result(evidence, canonical));

    CHECK(lab.asked.empty());
    CHECK(names_in(lab.folder).empty());
}

TEST_CASE("the result is timestamped as it is written: sign, the TSA, signature.json, "
          "timestamp.tst, and result.json last",
          "[evidence][timestamp][acceptance]")
{
    StampLab lab([] { return stamped(); });
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.write_attachments(facts_of(lab.run));
    REQUIRE(written.evidence);
    const std::string canonical = R"({"a":1})";
    SignedResult signature;
    rp::TimestampOutcome timestamp;

    REQUIRE_FALSE(builder.write_result(*written.evidence, canonical, &signature, &timestamp));

    CHECK(lab.order == std::vector<std::string>{"items.csv", "veeam-session.log", "sign",
                                                "timestamp", "signature.json", "timestamp.tst",
                                                "result.json"});
    // The TSA is asked about the bytes result.json holds: the hash the
    // signature signs.
    const std::array<unsigned char, 32> digest = rp::sha256_bytes(canonical);
    REQUIRE(lab.asked.size() == 1);
    CHECK(lab.asked.front() == std::vector<unsigned char>(digest.begin(), digest.end()));
    CHECK(rp::test::hex_from_bytes(lab.asked.front()) == signature.bundle_sha256);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "result.json",
                                                        "signature.json", "timestamp.tst",
                                                        "veeam-session.log"});
    CHECK(bytes_of(lab.folder / "timestamp.tst") == kToken);
    CHECK(bytes_of(lab.folder / "result.json") == canonical);
    CHECK(timestamp.stamped());
    CHECK(timestamp.token == kToken);
    CHECK(timestamp.gen_time == 1791288000);
    CHECK(timestamp.error.empty());
    CHECK(rp::kTimestampFileName == "timestamp.tst");
}

TEST_CASE("without a timestamper none is asked and no token is written", "[evidence][timestamp]")
{
    Lab lab;
    Evidence evidence;
    rp::TimestampOutcome timestamp = stamped();

    REQUIRE_FALSE(lab.builder().write_result(evidence, "{}", nullptr, &timestamp));

    CHECK(names_in(lab.folder) == std::set<std::string>{"result.json", "signature.json"});
    CHECK_FALSE(timestamp.stamped());
    CHECK(timestamp.error.empty());
    CHECK(timestamp.attempts == 0);
}

// --- W4.8 point 7: a run folder that was left without a result -------------------------
// What the service's close of such a folder needs of the builder: the text
// files that are there adopted as they are, the empty form of one that isn't,
// and the leftovers of a signing that didn't finish taken away.

namespace {

const std::string kCsvHeaderRow =
    "index,type,source,canary_id,name,expected_kind,sha256_rule,expected_sha256,found_sha256,"
    "restore_outcome,found,outcome,mismatches,verdict,code,ms\n";

void put(const std::filesystem::path& path, const std::string& content)
{
    std::ofstream file(path, std::ios::binary);
    file << content;
    REQUIRE(file.good());
}

const Attachment& named(const Evidence& evidence, const std::string& name)
{
    const auto it = std::ranges::find(evidence.attachments, name, &Attachment::name);
    REQUIRE(it != evidence.attachments.end());
    return *it;
}

} // namespace

TEST_CASE("adopting: a text file that is there but can't be read is an error, never replaced",
          "[evidence][adopt]")
{
    Lab lab;
    // A folder where the file should be: nothing the builder wrote.
    std::filesystem::create_directory(lab.folder / "items.csv");
    put(lab.folder / "veeam-session.log", "a line\n");

    const EvidenceBuilder::Written written = lab.builder().adopt_attachments();

    CHECK_FALSE(written.evidence);
    REQUIRE(written.errors.size() == 1);
    CHECK(written.errors[0].file == "items.csv");
    CHECK(written.errors[0].cause == EvidenceFailure::not_written);
    CHECK(std::filesystem::is_directory(lab.folder / "items.csv"));
    CHECK(bytes_of(lab.folder / "veeam-session.log") == "a line\n");
}

TEST_CASE("adopting: an empty form that can't be written is an error, and the other file is "
          "still tried",
          "[evidence][adopt]")
{
    const std::string refused = GENERATE("items.csv", "veeam-session.log");
    CAPTURE(refused);
    Lab lab;
    std::vector<std::string> tried;
    lab.options.write_file = [&](const std::filesystem::path& path, std::string_view) {
        tried.push_back(path.filename().string());
        return path.filename().string() != refused;
    };

    const EvidenceBuilder::Written written = lab.builder().adopt_attachments();

    CHECK_FALSE(written.evidence);
    REQUIRE(written.errors.size() == 1);
    CHECK(written.errors[0].file == refused);
    CHECK(written.errors[0].cause == EvidenceFailure::not_written);
    CHECK(tried == std::vector<std::string>{"items.csv", "veeam-session.log"});
}

TEST_CASE("adopting: a writer that throws is an error, never an exception", "[evidence][adopt]")
{
    Lab lab;
    lab.options.write_file = [](const std::filesystem::path&, std::string_view) -> bool {
        throw std::runtime_error("disk full");
    };

    const EvidenceBuilder::Written written = lab.builder().adopt_attachments();

    CHECK_FALSE(written.evidence);
    CHECK(written.errors.size() == 2);
}

TEST_CASE("adopting: the text files that are there are listed as they are, never rewritten",
          "[evidence][adopt]")
{
    Lab lab;
    const std::string csv = kCsvHeaderRow + "0,\"mail\",\"canary\"\n";
    const std::string log = "session s1 (mail): Success\n";
    put(lab.folder / "items.csv", csv);
    put(lab.folder / "veeam-session.log", log);
    int writes = 0;
    lab.options.write_file = [&](const std::filesystem::path&, std::string_view) {
        ++writes;
        return true;
    };

    const EvidenceBuilder::Written written = lab.builder().adopt_attachments();

    CHECK(written.errors.empty());
    REQUIRE(written.evidence);
    CHECK(writes == 0);
    REQUIRE(written.evidence->attachments.size() == 2);
    // Sorted by name, each with the hash and size of the bytes on disk.
    CHECK(written.evidence->attachments[0].name == "items.csv");
    CHECK(written.evidence->attachments[0].sha256 == rp::sha256_hex(csv));
    CHECK(written.evidence->attachments[0].size_bytes == csv.size());
    CHECK(written.evidence->attachments[1].name == "veeam-session.log");
    CHECK(written.evidence->attachments[1].sha256 == rp::sha256_hex(log));
    CHECK(written.evidence->attachments[1].size_bytes == log.size());
    CHECK(bytes_of(lab.folder / "items.csv") == csv);
    CHECK(bytes_of(lab.folder / "veeam-session.log") == log);
}

TEST_CASE("adopting: a text file that isn't there is written in its empty form: the CSV's "
          "header alone, an empty log",
          "[evidence][adopt]")
{
    const auto [has_csv, has_log] = GENERATE(table<bool, bool>({
        {false, false},
        {true, false},
        {false, true},
    }));
    CAPTURE(has_csv, has_log);
    Lab lab;
    const std::string csv = kCsvHeaderRow + "0,\"mail\"\n";
    const std::string log = "a line\n";
    if (has_csv) {
        put(lab.folder / "items.csv", csv);
    }
    if (has_log) {
        put(lab.folder / "veeam-session.log", log);
    }

    const EvidenceBuilder::Written written = lab.builder().adopt_attachments();

    CHECK(written.errors.empty());
    REQUIRE(written.evidence);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
    const std::string csv_now = has_csv ? csv : kCsvHeaderRow;
    const std::string log_now = has_log ? log : std::string{};
    CHECK(bytes_of(lab.folder / "items.csv") == csv_now);
    CHECK(bytes_of(lab.folder / "veeam-session.log") == log_now);
    CHECK(named(*written.evidence, "items.csv").sha256 == rp::sha256_hex(csv_now));
    CHECK(named(*written.evidence, "veeam-session.log").sha256 == rp::sha256_hex(log_now));
    CHECK(named(*written.evidence, "veeam-session.log").size_bytes == log_now.size());
    // The empty CSV is the one a run with no expected set writes.
    CHECK(kCsvHeaderRow == EvidenceBuilder::items_csv({}).text);
    CHECK(EvidenceBuilder::session_log(nullptr).text.empty());
}

TEST_CASE("adopting with `replace`: both text files are replaced by their empty forms, whatever "
          "they held",
          "[evidence][adopt]")
{
    Lab lab;
    put(lab.folder / "items.csv", kCsvHeaderRow + "0,\"changed after it was hashed\"\n");
    put(lab.folder / "veeam-session.log", "a line\n");

    const EvidenceBuilder::Written written = lab.builder().adopt_attachments(true);

    CHECK(written.errors.empty());
    REQUIRE(written.evidence);
    CHECK(bytes_of(lab.folder / "items.csv") == kCsvHeaderRow);
    CHECK(bytes_of(lab.folder / "veeam-session.log") == std::string{});
    CHECK(named(*written.evidence, "items.csv").sha256 == rp::sha256_hex(kCsvHeaderRow));
    CHECK(named(*written.evidence, "veeam-session.log").size_bytes == 0);
}

TEST_CASE("adopting with `replace`: a file that can't be taken away is an error",
          "[evidence][adopt]")
{
    Lab lab;
    // Not a file, and not empty: remove() leaves it.
    std::filesystem::create_directory(lab.folder / "veeam-session.log");
    put(lab.folder / "veeam-session.log" / "inside", "x");

    const EvidenceBuilder::Written written = lab.builder().adopt_attachments(true);

    CHECK_FALSE(written.evidence);
    REQUIRE(written.errors.size() == 1);
    CHECK(written.errors[0].file == "veeam-session.log");
    CHECK(bytes_of(lab.folder / "items.csv") == kCsvHeaderRow);
}

TEST_CASE("adopting: the screenshot is unavailable, `disabled` or `no_page` by the client's "
          "setting, and the capturer is never asked",
          "[evidence][adopt][screenshot]")
{
    const bool enabled = GENERATE(false, true);
    Lab lab;
    lab.options.screenshots_enabled = enabled;
    int captures = 0;
    lab.options.capture = [&](const ScreenshotRequest&) -> std::optional<ScreenshotReason> {
        ++captures;
        return std::nullopt;
    };

    const EvidenceBuilder::Written written = lab.builder().adopt_attachments();

    REQUIRE(written.evidence);
    CHECK_FALSE(written.evidence->screenshot.captured);
    CHECK(written.evidence->screenshot.reason ==
          (enabled ? ScreenshotReason::no_page : ScreenshotReason::disabled));
    CHECK(captures == 0);
}

TEST_CASE("an adopted folder is signed and written as a run's own is", "[evidence][adopt]")
{
    Lab lab;
    put(lab.folder / "items.csv", kCsvHeaderRow + "0,\"mail\"\n");
    EvidenceBuilder builder = lab.builder();
    const EvidenceBuilder::Written written = builder.adopt_attachments();
    REQUIRE(written.evidence);
    SignedResult signature;

    REQUIRE_FALSE(builder.write_result(*written.evidence, R"({"a":1})", &signature));

    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "result.json",
                                                        "signature.json", "veeam-session.log"});
    CHECK(bytes_of(lab.folder / "signature.json") == signature.signature_file);
}

TEST_CASE("adopting: a text file that is there only under another case of its name is no "
          "attachment: it is taken away and the empty form written under the exact name",
          "[evidence][adopt]")
{
    // NTFS opens ITEMS.CSV for items.csv, but the verifiers read a file only
    // when the folder's listing has its name byte for byte.
    const bool replace = GENERATE(false, true);
    CAPTURE(replace);
    Lab lab;
    put(lab.folder / "ITEMS.CSV", kCsvHeaderRow + "0,\"not the run's\"\n");
    const std::string log = "a line\n";
    put(lab.folder / "veeam-session.log", log);
    EvidenceBuilder builder = lab.builder();

    const EvidenceBuilder::Written written = builder.adopt_attachments(replace);

    CHECK(written.errors.empty());
    REQUIRE(written.evidence);
    CHECK(names_in(lab.folder) == std::set<std::string>{"items.csv", "veeam-session.log"});
    CHECK(bytes_of(lab.folder / "items.csv") == kCsvHeaderRow);
    CHECK(named(*written.evidence, "items.csv").sha256 == rp::sha256_hex(kCsvHeaderRow));
    CHECK(named(*written.evidence, "items.csv").size_bytes == kCsvHeaderRow.size());
    // The file under its exact name is the run's own, kept unless replaced.
    CHECK(bytes_of(lab.folder / "veeam-session.log") == (replace ? std::string{} : log));

    // And the folder closed over it verifies.
    nlohmann::json document = nlohmann::json::parse(
        rp::test::read_shared("testdata/result-v1/valid.json"));
    document["attachments"] = rp::to_json(written.evidence->attachments);
    SignedResult signature;
    REQUIRE_FALSE(
        builder.write_result(*written.evidence, rp::canonical_json(document), &signature));
    const rp::Verification verified = rp::Signer::verify_folder(
        rp::folder_reader(lab.folder), *rp::list_folder(lab.folder),
        rp::test::public_key_of(*lab.key));
    CHECK(rp::to_string(verified.word) == "verified");
}

TEST_CASE("adopting: a file under another case of a text file's name that can't be taken away "
          "is an error",
          "[evidence][adopt]")
{
    Lab lab;
    std::filesystem::create_directory(lab.folder / "Items.csv");
    put(lab.folder / "Items.csv" / "inside", "x");

    const EvidenceBuilder::Written written = lab.builder().adopt_attachments();

    CHECK_FALSE(written.evidence);
    REQUIRE(written.errors.size() == 1);
    CHECK(written.errors[0].file == "items.csv");
    CHECK(written.errors[0].cause == EvidenceFailure::not_written);
    CHECK(names_in(lab.folder) == std::set<std::string>{"Items.csv", "veeam-session.log"});
}

TEST_CASE("adopting: a folder that can't be listed gives no evidence", "[evidence][adopt]")
{
    Lab lab;
    EvidenceBuilder builder(lab.dir.path() / "no such folder", lab.options);

    const EvidenceBuilder::Written written = builder.adopt_attachments();

    CHECK_FALSE(written.evidence);
    CHECK_FALSE(written.errors.empty());
}

TEST_CASE("the leftovers of a signing that didn't finish are taken away: signature.json, "
          "timestamp.tst, screenshot.png and the atomic writer's temp files, nothing else",
          "[evidence][adopt]")
{
    Lab lab;
    const std::vector<std::string> leftovers{
        "signature.json",
        "timestamp.tst",
        "screenshot.png",
        "result.json.0123456789abcdef.tmp",
        "items.csv.fedcba9876543210.tmp",
        "anything.0000000000000000.tmp",
        // Windows names a file whatever its letters' case.
        "SIGNATURE.JSON.0123456789abcdef.tmp",
    };
    const std::vector<std::string> kept{
        "items.csv",
        "veeam-session.log",
        "notes.txt",
        // Not the writer's temp name: 15 digits, 17, upper case, no name before it.
        "result.json.0123456789abcde.tmp",
        "result.json.0123456789abcdef0.tmp",
        "other.0123456789ABCDEF.tmp",
        ".0123456789abcdef.tmp",
        "result.json.0123456789abcdef.tmp.bak",
        "signature.json.bak",
    };
    for (const std::string& name : leftovers) {
        put(lab.folder / name, "left");
    }
    for (const std::string& name : kept) {
        put(lab.folder / name, "kept");
    }

    CHECK(EvidenceBuilder::remove_unfinished(lab.folder));

    CHECK(names_in(lab.folder) == std::set<std::string>(kept.begin(), kept.end()));
    for (const std::string& name : kept) {
        CHECK(bytes_of(lab.folder / name) == "kept");
    }
    // Done twice, it does nothing more.
    CHECK(EvidenceBuilder::remove_unfinished(lab.folder));
    CHECK(names_in(lab.folder) == std::set<std::string>(kept.begin(), kept.end()));
}

TEST_CASE("leftovers under another case of their names are taken away too", "[evidence][adopt]")
{
    Lab lab;
    put(lab.folder / "Signature.JSON", "left");
    put(lab.folder / "TIMESTAMP.tst", "left");

    CHECK(EvidenceBuilder::remove_unfinished(lab.folder));

    CHECK(names_in(lab.folder).empty());
}

TEST_CASE("a leftover that can't be taken away, and a folder that isn't there, are said",
          "[evidence][adopt]")
{
    Lab lab;
    // A folder with something in it under the signature's name.
    std::filesystem::create_directory(lab.folder / "signature.json");
    put(lab.folder / "signature.json" / "inside", "x");
    put(lab.folder / "timestamp.tst", "left");

    CHECK_FALSE(EvidenceBuilder::remove_unfinished(lab.folder));
    // What could go went.
    CHECK(names_in(lab.folder) == std::set<std::string>{"signature.json"});

    CHECK_FALSE(EvidenceBuilder::remove_unfinished(lab.dir.path() / "no such folder"));
}
