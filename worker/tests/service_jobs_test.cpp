// The service's jobs reader (rp/service_jobs.hpp; W4.8, docs/decisions.md
// 2026-10-08 points 3 and 4): which file runs nothing and with which words,
// and for each job whether it has no usable run_id (J1), is invalid with its
// first key at fault (J3), or is a job. Failure paths first.

#include "result_lab.hpp"
#include "schema_walk.hpp"
#include "test_support.hpp"

#include <rp/canonical_json.hpp>
#include <rp/service_jobs.hpp>
#include <rp/sha256.hpp>
#include <rp/vault.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

using nlohmann::json;
using rp::test::TempDir;

namespace {

// The client's profile a job carries (W4.10): the shared vectors' valid one.
const json& profile()
{
    static const json value =
        json::parse(rp::test::read_shared("testdata/client-profile-v1/valid.json"));
    return value;
}

// A job that passes every rule.
json valid_job()
{
    return json{{"run_id", "job-0001"},
                {"client_id", "client-7"},
                {"client", profile()},
                {"connector", json{{"type", "veeam_m365"}}},
                {"sample_mail", 5},
                {"sample_sp", 3},
                {"sample_od", 2},
                {"restore_point", "latest"},
                {"screenshots_enabled", false}};
}

// `job` with its client's `key` set to `value`.
json with_client(json job, const char* key, json value)
{
    job["client"][key] = std::move(value);
    return job;
}

std::string document_of(const json& jobs)
{
    return json{{"format", "restoreproof.jobs.v1"}, {"jobs", jobs}}.dump();
}

// The one entry of a document holding `job` alone.
rp::JobEntry entry_of(const json& job)
{
    const rp::JobsDocument document = rp::parse_jobs(document_of(json::array({job})));
    REQUIRE(document.state == rp::JobsState::read);
    REQUIRE(document.jobs.size() == 1);
    return document.jobs.front();
}

json with(json job, const char* key, json value)
{
    job[key] = std::move(value);
    return job;
}

json without(json job, const char* key)
{
    job.erase(key);
    return job;
}

} // namespace

// --- The file ---------------------------------------------------------------

TEST_CASE("jobs: a file that can't be believed or read runs nothing, with its fixed words",
          "[service_jobs]")
{
    struct Row {
        rp::TrustedRead state;
        rp::JobsFault fault;
        const char* line;
    };
    const Row row = GENERATE(
        Row{rp::TrustedRead::unreadable, rp::JobsFault::unreadable,
            R"(jobs error: C:\lab\jobs.json: can't be read)"},
        Row{rp::TrustedRead::not_trusted, rp::JobsFault::not_trusted,
            R"(jobs error: C:\lab\jobs.json: owned by neither SYSTEM, Administrators nor this account)"},
        Row{rp::TrustedRead::too_large, rp::JobsFault::too_large,
            R"(jobs error: C:\lab\jobs.json: over 1 MiB)"});
    const std::filesystem::path file = R"(C:\lab\jobs.json)";
    std::vector<std::uintmax_t> limits;
    std::vector<std::filesystem::path> asked;

    const rp::JobsDocument document =
        rp::read_jobs(file, [&](const std::filesystem::path& path, std::uintmax_t max_bytes) {
            asked.push_back(path);
            limits.push_back(max_bytes);
            // Bytes a reader must not have handed on are never parsed.
            return rp::TrustedFile{row.state, std::string{}};
        });

    CHECK(document.state == rp::JobsState::error);
    REQUIRE(document.fault.has_value());
    CHECK(*document.fault == row.fault);
    CHECK(document.jobs.empty());
    CHECK(document.sha256.empty());
    CHECK(rp::jobs_error_line(file, *document.fault) == row.line);
    CHECK(asked == std::vector<std::filesystem::path>{file});
    CHECK(limits == std::vector<std::uintmax_t>{1024u * 1024u});
}

TEST_CASE("jobs: a file that isn't there is no jobs and no error", "[service_jobs]")
{
    SECTION("as the reader says")
    {
        const rp::JobsDocument document =
            rp::read_jobs(R"(C:\lab\jobs.json)", [](const std::filesystem::path&, std::uintmax_t) {
                return rp::TrustedFile{rp::TrustedRead::absent, {}};
            });
        CHECK(document.state == rp::JobsState::no_file);
        CHECK_FALSE(document.fault.has_value());
        CHECK(document.jobs.empty());
        CHECK(document.sha256.empty());
    }
    SECTION("through the real read")
    {
        const TempDir tmp;
        const rp::JobsDocument document = rp::read_jobs(tmp.path() / "jobs.json");
        CHECK(document.state == rp::JobsState::no_file);
        CHECK_FALSE(document.fault.has_value());
    }
}

TEST_CASE("jobs: a document that isn't one runs nothing", "[service_jobs]")
{
    struct Row {
        const char* name;
        std::string text;
        rp::JobsFault fault;
        const char* words;
    };
    const std::string job = valid_job().dump();
    const Row row = GENERATE_COPY(
        Row{"empty", "", rp::JobsFault::not_json, "not JSON"},
        Row{"not JSON", "{\"format\":", rp::JobsFault::not_json, "not JSON"},
        Row{"text after the document", document_of(json::array()) + "x", rp::JobsFault::not_json,
            "not JSON"},
        Row{"bytes that aren't UTF-8", "{\"format\":\"\xff\",\"jobs\":[]}",
            rp::JobsFault::not_json, "not JSON"},
        Row{"a top-level key twice",
            R"({"format":"restoreproof.jobs.v1","jobs":[],"jobs":[]})", rp::JobsFault::not_json,
            "not JSON"},
        Row{"the format twice",
            R"({"format":"restoreproof.jobs.v0","format":"restoreproof.jobs.v1","jobs":[]})",
            rp::JobsFault::not_json, "not JSON"},
        Row{"a job's key twice",
            R"({"format":"restoreproof.jobs.v1","jobs":[{"run_id":"a","run_id":"b"}]})",
            rp::JobsFault::not_json, "not JSON"},
        Row{"a key twice below a job",
            R"({"format":"restoreproof.jobs.v1","jobs":[{"client_id":{"a":1,"a":2}}]})",
            rp::JobsFault::not_json, "not JSON"},
        Row{"an array", "[" + job + "]", rp::JobsFault::not_document,
            "not a restoreproof.jobs.v1 document"},
        Row{"a string", R"("restoreproof.jobs.v1")", rp::JobsFault::not_document,
            "not a restoreproof.jobs.v1 document"},
        Row{"another format", R"({"format":"restoreproof.jobs.v2","jobs":[]})",
            rp::JobsFault::not_document, "not a restoreproof.jobs.v1 document"},
        Row{"the format no string", R"({"format":1,"jobs":[]})", rp::JobsFault::not_document,
            "not a restoreproof.jobs.v1 document"},
        Row{"no format", R"({"jobs":[]})", rp::JobsFault::not_document,
            "not a restoreproof.jobs.v1 document"},
        Row{"no jobs", R"({"format":"restoreproof.jobs.v1"})", rp::JobsFault::not_document,
            "not a restoreproof.jobs.v1 document"},
        Row{"jobs an object", R"({"format":"restoreproof.jobs.v1","jobs":{}})",
            rp::JobsFault::not_document, "not a restoreproof.jobs.v1 document"},
        Row{"jobs null", R"({"format":"restoreproof.jobs.v1","jobs":null})",
            rp::JobsFault::not_document, "not a restoreproof.jobs.v1 document"},
        Row{"another top-level key", R"({"format":"restoreproof.jobs.v1","jobs":[],"next":1})",
            rp::JobsFault::not_document, "not a restoreproof.jobs.v1 document"},
        Row{"another key in place of jobs", R"({"format":"restoreproof.jobs.v1","job":[]})",
            rp::JobsFault::not_document, "not a restoreproof.jobs.v1 document"},
        Row{"a sixth job",
            document_of(json::array({valid_job(), valid_job(), valid_job(), valid_job(),
                                     valid_job(), valid_job()})),
            rp::JobsFault::too_many, "more than 5 jobs"},
        Row{"six entries that are no jobs", document_of(json::array({1, 2, 3, 4, 5, 6})),
            rp::JobsFault::too_many, "more than 5 jobs"});
    CAPTURE(row.name);

    const rp::JobsDocument document = rp::parse_jobs(row.text);

    CHECK(document.state == rp::JobsState::error);
    REQUIRE(document.fault.has_value());
    CHECK(*document.fault == row.fault);
    CHECK(rp::to_text(*document.fault) == row.words);
    CHECK(document.jobs.empty());
    // What was read is named, so the loop can tell when it changed.
    CHECK(document.sha256 == rp::sha256_hex(row.text));
}

TEST_CASE("jobs: a document nested past the limit is not JSON to the reader: 50,000 levels in "
          "a file under 1 MiB",
          "[service_jobs]")
{
    const auto nested = [](std::size_t levels) {
        return R"({"format":"restoreproof.jobs.v1","jobs":[)" + std::string(levels, '[') +
               std::string(levels, ']') + "]}";
    };
    const std::string deep = nested(50'000);
    REQUIRE(deep.size() < rp::kMaxJobsFileBytes);

    const rp::JobsDocument refused = rp::parse_jobs(deep);
    CHECK(refused.state == rp::JobsState::error);
    CHECK(refused.fault == rp::JobsFault::not_json);
    CHECK(refused.jobs.empty());
    CHECK(refused.sha256 == rp::sha256_hex(deep));

    // The document's two levels and thirty more are the most that is read.
    CHECK(rp::parse_jobs(nested(rp::kMaxJsonNesting - 1)).fault == rp::JobsFault::not_json);
    const rp::JobsDocument read = rp::parse_jobs(nested(rp::kMaxJsonNesting - 2));
    CHECK(read.state == rp::JobsState::read);
    REQUIRE(read.jobs.size() == 1);
    CHECK(read.jobs[0].state == rp::JobState::no_run_id);
}

// --- A job ------------------------------------------------------------------

TEST_CASE("jobs: a job without a usable run_id is J1, with its position", "[service_jobs]")
{
    struct Row {
        const char* name;
        json job;
    };
    const Row row = GENERATE_COPY(
        Row{"no run_id", without(valid_job(), "run_id")},
        Row{"a number", with(valid_job(), "run_id", 7)},
        Row{"null", with(valid_job(), "run_id", nullptr)},
        Row{"empty", with(valid_job(), "run_id", "")},
        Row{"a colon, which can't name a folder", with(valid_job(), "run_id", "job:1")},
        Row{"a device's name", with(valid_job(), "run_id", "PRN")},
        Row{"a device's name with an extension", with(valid_job(), "run_id", "aux.json")},
        Row{"a dot at its end", with(valid_job(), "run_id", "job-1.")},
        Row{"two dots", with(valid_job(), "run_id", "..")},
        Row{"a space", with(valid_job(), "run_id", "job 1")},
        Row{"a backslash", with(valid_job(), "run_id", "a\\b")},
        Row{"a line break", with(valid_job(), "run_id", "job-1\nSECURITY: forged")},
        Row{"129 characters", with(valid_job(), "run_id", std::string(129, 'a'))},
        Row{"a letter outside ASCII", with(valid_job(), "run_id", "j\xc3\xb6" "b")},
        Row{"a job that is a string", json("job-0001")},
        Row{"a job that is an array", json::array({"run_id", "job-0001"})},
        Row{"a job that is null", json(nullptr)});
    CAPTURE(row.name);

    const rp::JobsDocument document =
        rp::parse_jobs(document_of(json::array({valid_job(), row.job})));

    REQUIRE(document.state == rp::JobsState::read);
    REQUIRE(document.jobs.size() == 2);
    CHECK(document.jobs[0].state == rp::JobState::valid);
    CHECK(document.jobs[0].position == 1);
    const rp::JobEntry& entry = document.jobs[1];
    CHECK(entry.state == rp::JobState::no_run_id);
    CHECK(entry.position == 2);
    CHECK(entry.fault.empty());
    // Nothing of such a job is handed on.
    CHECK(entry.job.run_id.empty());
    CHECK_FALSE(entry.job.client_id.has_value());
}

TEST_CASE("jobs: a job with a usable run_id and a broken rule is J3, with the first key at fault",
          "[service_jobs]")
{
    struct Row {
        const char* name;
        json job;
        const char* fault;
    };
    const json big = json::parse("18446744073709551615");
    const Row row = GENERATE_COPY(
        // client_id
        Row{"no client_id", without(valid_job(), "client_id"), "client_id"},
        Row{"client_id a number", with(valid_job(), "client_id", 7), "client_id"},
        Row{"client_id empty", with(valid_job(), "client_id", ""), "client_id"},
        Row{"client_id of 129 characters", with(valid_job(), "client_id", std::string(129, 'c')),
            "client_id"},
        Row{"client_id with a tab", with(valid_job(), "client_id", "a\tb"), "client_id"},
        Row{"client_id with DEL", with(valid_job(), "client_id", "a\x7f"), "client_id"},
        Row{"client_id outside ASCII", with(valid_job(), "client_id", "kund\xc3\xa9"),
            "client_id"},
        // the client (W4.10 point 2)
        Row{"no client", without(valid_job(), "client"), "client"},
        Row{"client a string", with(valid_job(), "client", "contoso"), "client"},
        Row{"client null", with(valid_job(), "client", nullptr), "client"},
        Row{"client an empty object", with(valid_job(), "client", json::object()), "client"},
        Row{"client of another format", with_client(valid_job(), "format", "restoreproof.jobs.v1"),
            "client"},
        Row{"client with a key that isn't the profile's",
            with_client(valid_job(), "client_id", "client-7"), "client"},
        Row{"client without its mailbox",
            with(valid_job(), "client", without(profile(), "test_mailbox")), "client.test_mailbox"},
        Row{"client with a tenant that isn't a GUID",
            with_client(valid_job(), "graph_tenant_id", "contoso.onmicrosoft.com"),
            "client.graph_tenant_id"},
        Row{"client with another mailbox",
            with_client(valid_job(), "test_mailbox", "alice@contoso.onmicrosoft.com"),
            "client.test_mailbox"},
        Row{"client with a list GUID for the library",
            with_client(valid_job(), "test_library_id", "ffec069d-65e4-4c3a-9da2-ac086cf9dafa"),
            "client.test_library_id"},
        Row{"client with a folder ID that can't be one",
            with_client(valid_job(), "test_onedrive_folder_id", "01/ABC"),
            "client.test_onedrive_folder_id"},
        Row{"client with a control character in the organisation's name",
            with_client(valid_job(), "veeam_org_name", "a\nb"), "client.veeam_org_name"},
        // the connector (W4.11 point 5)
        Row{"no connector", without(valid_job(), "connector"), "connector"},
        Row{"connector a string", with(valid_job(), "connector", "veeam_m365"), "connector"},
        Row{"connector null", with(valid_job(), "connector", nullptr), "connector"},
        Row{"connector an empty object", with(valid_job(), "connector", json::object()),
            "connector"},
        Row{"connector with a key beside type",
            with(valid_job(), "connector", json{{"type", "veeam_m365"}, {"api", "v8"}}),
            "connector"},
        Row{"connector.type a number", with(valid_job(), "connector", json{{"type", 1}}),
            "connector.type"},
        Row{"connector.type empty", with(valid_job(), "connector", json{{"type", ""}}),
            "connector.type"},
        Row{"connector.type with a space",
            with(valid_job(), "connector", json{{"type", "veeam m365"}}), "connector.type"},
        Row{"connector.type in capitals",
            with(valid_job(), "connector", json{{"type", "Veeam_M365"}}), "connector.type"},
        Row{"connector.type of 65 characters",
            with(valid_job(), "connector", json{{"type", std::string(65, 'a')}}),
            "connector.type"},
        // the sizes
        Row{"no sample_mail", without(valid_job(), "sample_mail"), "sample_mail"},
        Row{"sample_mail a string", with(valid_job(), "sample_mail", "5"), "sample_mail"},
        Row{"sample_mail a float", with(valid_job(), "sample_mail", 5.0), "sample_mail"},
        Row{"sample_mail negative", with(valid_job(), "sample_mail", -1), "sample_mail"},
        Row{"sample_mail 101", with(valid_job(), "sample_mail", 101), "sample_mail"},
        Row{"sample_mail past the signed range", with(valid_job(), "sample_mail", big),
            "sample_mail"},
        Row{"no sample_sp", without(valid_job(), "sample_sp"), "sample_sp"},
        Row{"sample_sp a boolean", with(valid_job(), "sample_sp", true), "sample_sp"},
        Row{"sample_sp 101", with(valid_job(), "sample_sp", 101), "sample_sp"},
        Row{"no sample_od", without(valid_job(), "sample_od"), "sample_od"},
        Row{"sample_od null", with(valid_job(), "sample_od", nullptr), "sample_od"},
        Row{"sample_od -1", with(valid_job(), "sample_od", -1), "sample_od"},
        Row{"all three sizes 0",
            with(with(with(valid_job(), "sample_mail", 0), "sample_sp", 0), "sample_od", 0),
            "sample_mail"},
        // restore_point
        Row{"no restore_point", without(valid_job(), "restore_point"), "restore_point"},
        Row{"restore_point a number", with(valid_job(), "restore_point", 1), "restore_point"},
        Row{"restore_point empty", with(valid_job(), "restore_point", ""), "restore_point"},
        Row{"restore_point with a space", with(valid_job(), "restore_point", "the latest"),
            "restore_point"},
        Row{"restore_point of 129 characters",
            with(valid_job(), "restore_point", std::string(129, 'a')), "restore_point"},
        // screenshots_enabled
        Row{"no screenshots_enabled", without(valid_job(), "screenshots_enabled"),
            "screenshots_enabled"},
        Row{"screenshots_enabled a number", with(valid_job(), "screenshots_enabled", 0),
            "screenshots_enabled"},
        Row{"screenshots_enabled a string", with(valid_job(), "screenshots_enabled", "false"),
            "screenshots_enabled"},
        // canary_cursor
        Row{"canary_cursor a string", with(valid_job(), "canary_cursor", "0,0,0"),
            "canary_cursor"},
        Row{"canary_cursor null", with(valid_job(), "canary_cursor", nullptr), "canary_cursor"},
        Row{"canary_cursor of two", with(valid_job(), "canary_cursor", json::array({0, 0})),
            "canary_cursor"},
        Row{"canary_cursor of four",
            with(valid_job(), "canary_cursor", json::array({0, 0, 0, 0})), "canary_cursor"},
        Row{"a cursor of 1000000",
            with(valid_job(), "canary_cursor", json::array({0, 1000000, 0})), "canary_cursor"},
        Row{"a cursor of -1", with(valid_job(), "canary_cursor", json::array({0, 0, -1})),
            "canary_cursor"},
        Row{"a cursor that is a float",
            with(valid_job(), "canary_cursor", json::array({0.5, 0, 0})), "canary_cursor"},
        Row{"a cursor that is a string",
            with(valid_job(), "canary_cursor", json::array({"0", 0, 0})), "canary_cursor"},
        Row{"a cursor past the signed range",
            with(valid_job(), "canary_cursor", json::array({0, 0, big})), "canary_cursor"},
        // a closed object
        Row{"an unknown key", with(valid_job(), "profile", json::object()), "unknown key"},
        Row{"a known key in another case", with(valid_job(), "Sample_mail", 5), "unknown key"},
        // the first in the fixed order, whatever else is wrong
        Row{"a size and the point", with(with(valid_job(), "restore_point", 1), "sample_sp", -1),
            "sample_sp"},
        Row{"a known key at fault and an unknown one",
            with(with(valid_job(), "profile", 1), "screenshots_enabled", 1),
            "screenshots_enabled"},
        Row{"a bad client and a bad size", with(without(valid_job(), "client"), "sample_od", -1),
            "client"},
        Row{"a bad client_id and a bad client",
            with(without(valid_job(), "client"), "client_id", 7), "client_id"});
    CAPTURE(row.name);

    const rp::JobEntry entry = entry_of(row.job);

    CHECK(entry.state == rp::JobState::invalid);
    CHECK(entry.position == 1);
    CHECK(entry.fault == row.fault);
    CHECK(entry.job.run_id == "job-0001");
    // Its client, when that could be read; nothing else of a job that is none.
    if (std::string{row.fault} == "client_id") {
        CHECK_FALSE(entry.job.client_id.has_value());
    } else {
        CHECK(entry.job.client_id == std::optional<std::string>{"client-7"});
    }
    // And its profile, when that could be read (W4.10): a J3 record carries
    // it, so the job's result names the client.
    if (std::string{row.fault} == "client_id" || std::string_view{row.fault}.starts_with("client")) {
        CHECK_FALSE(entry.job.client.has_value());
    } else {
        REQUIRE(entry.job.client.has_value());
        CHECK(rp::to_json(*entry.job.client) == profile());
    }
    CHECK(entry.job.sample_mail == 0);
    CHECK(entry.job.sample_sp == 0);
    CHECK(entry.job.sample_od == 0);
    CHECK(entry.job.restore_point.empty());
    CHECK_FALSE(entry.job.screenshots_enabled);
    CHECK_FALSE(entry.job.canary_cursor.has_value());
}

TEST_CASE("jobs: an invalid job with a null client_id names no client", "[service_jobs]")
{
    const rp::JobEntry entry =
        entry_of(with(with(valid_job(), "client_id", nullptr), "sample_od", 500));

    CHECK(entry.state == rp::JobState::invalid);
    CHECK(entry.fault == "sample_od");
    CHECK_FALSE(entry.job.client_id.has_value());
}

// --- Valid ------------------------------------------------------------------

TEST_CASE("jobs: a valid job is read as it is written", "[service_jobs]")
{
    SECTION("every key")
    {
        json job = valid_job();
        job["canary_cursor"] = json::array({1, 999999, 0});
        job["screenshots_enabled"] = true;
        job["restore_point"] = "0a1b2c3d-0000-4000-8000-000000000001";
        job["client_id"] = std::string(128, 'c');
        job["sample_mail"] = 100;
        job["sample_sp"] = 0;
        job["sample_od"] = 0;
        job["run_id"] = "rp-20261008T101112Z-0a1b2c3d";

        const rp::JobEntry entry = entry_of(job);

        CHECK(entry.state == rp::JobState::valid);
        CHECK(entry.position == 1);
        CHECK(entry.fault.empty());
        CHECK(entry.job.run_id == "rp-20261008T101112Z-0a1b2c3d");
        CHECK(entry.job.client_id == std::optional<std::string>{std::string(128, 'c')});
        CHECK(entry.job.sample_mail == 100);
        CHECK(entry.job.sample_sp == 0);
        CHECK(entry.job.sample_od == 0);
        CHECK(entry.job.restore_point == "0a1b2c3d-0000-4000-8000-000000000001");
        CHECK(entry.job.screenshots_enabled);
        REQUIRE(entry.job.canary_cursor.has_value());
        CHECK(entry.job.canary_cursor->mail == 1);
        CHECK(entry.job.canary_cursor->sharepoint == 999999);
        CHECK(entry.job.canary_cursor->onedrive == 0);
        CHECK(entry.job.connector_type == "veeam_m365");
    }
    SECTION("a connector type the reader can't know is read as written: the loop decides (W4.11)")
    {
        const rp::JobEntry entry =
            entry_of(with(valid_job(), "connector", json{{"type", "other_backup"}}));
        CHECK(entry.state == rp::JobState::valid);
        CHECK(entry.job.connector_type == "other_backup");
    }
    SECTION("no cursor is 0,0,0, a null client_id no client, and latest stays as written")
    {
        const rp::JobEntry entry =
            entry_of(with(with(valid_job(), "client_id", nullptr), "restore_point", "Latest"));

        CHECK(entry.state == rp::JobState::valid);
        CHECK_FALSE(entry.job.client_id.has_value());
        CHECK(entry.job.sample_mail == 5);
        CHECK(entry.job.sample_sp == 3);
        CHECK(entry.job.sample_od == 2);
        CHECK(entry.job.restore_point == "Latest");
        CHECK_FALSE(entry.job.screenshots_enabled);
        // W6.2: no canary_cursor key, so no canaries.
        CHECK_FALSE(entry.job.canary_cursor.has_value());
    }
}

TEST_CASE("jobs: a document's entries keep its order, each decided by itself", "[service_jobs]")
{
    SECTION("no jobs")
    {
        const rp::JobsDocument document = rp::parse_jobs(document_of(json::array()));
        CHECK(document.state == rp::JobsState::read);
        CHECK_FALSE(document.fault.has_value());
        CHECK(document.jobs.empty());
    }
    SECTION("five of every kind, written with white space and a byte order mark")
    {
        const json jobs = json::array({with(valid_job(), "run_id", "job-a"),
                                       with(valid_job(), "run_id", "job:b"),
                                       with(with(valid_job(), "run_id", "job-c"), "sample_sp", -1),
                                       with(valid_job(), "run_id", "job-d"),
                                       with(valid_job(), "run_id", "job-a")});
        const std::string text = "\xef\xbb\xbf" +
                                 json{{"jobs", jobs}, {"format", "restoreproof.jobs.v1"}}.dump(2) +
                                 "\r\n";

        const rp::JobsDocument document = rp::parse_jobs(text);

        REQUIRE(document.state == rp::JobsState::read);
        CHECK(document.sha256 == rp::sha256_hex(text));
        REQUIRE(document.jobs.size() == 5);
        const auto state = [&](std::size_t i) { return document.jobs[i].state; };
        CHECK(state(0) == rp::JobState::valid);
        CHECK(state(1) == rp::JobState::no_run_id);
        CHECK(state(2) == rp::JobState::invalid);
        CHECK(state(3) == rp::JobState::valid);
        // The same run twice is the loop's to skip (J2), not the reader's.
        CHECK(state(4) == rp::JobState::valid);
        for (std::size_t i = 0; i < document.jobs.size(); ++i) {
            CHECK(document.jobs[i].position == i + 1);
        }
        CHECK(document.jobs[0].job.run_id == "job-a");
        CHECK(document.jobs[2].job.run_id == "job-c");
        CHECK(document.jobs[2].fault == "sample_sp");
        CHECK(document.jobs[3].job.run_id == "job-d");
    }
}

TEST_CASE("jobs: a file of this account's is read from disk whole", "[service_jobs][acceptance]")
{
    const TempDir tmp;
    const std::string text = document_of(json::array({valid_job()}));
    const std::filesystem::path file = tmp.write("jobs.json", text);

    const rp::JobsDocument document = rp::read_jobs(file);

    REQUIRE(document.state == rp::JobsState::read);
    CHECK(document.sha256 == rp::sha256_hex(text));
    REQUIRE(document.jobs.size() == 1);
    CHECK(document.jobs[0].state == rp::JobState::valid);
    CHECK(document.jobs[0].job.run_id == "job-0001");

    // And a folder at the path can't be read.
    const rp::JobsDocument folder = rp::read_jobs(tmp.path());
    CHECK(folder.state == rp::JobsState::error);
    CHECK(folder.fault == std::optional<rp::JobsFault>{rp::JobsFault::unreadable});
}

// --- the shared jobs vectors (W4.10 point 8) ---------------------------------

TEST_CASE("jobs: the jobs schema is in the shared subset, its client the profile schema's file",
          "[service_jobs][schema]")
{
    const std::string text = rp::test::read_shared("schemas/jobs.v1.json");
    const json schema = json::parse(text);
    CHECK(rp::test::problems_of(schema) == std::vector<std::string>{});
    CHECK(text.find('\r') == std::string::npos);
    CHECK(schema.at("properties").at("format").at("const") == std::string{rp::kJobsFormat});
    const json& job = schema.at("$defs").at("job");
    CHECK(job.at("additionalProperties") == false);
    CHECK(job.at("properties").at("client") == json{{"$ref", "client-profile.v1.json"}});
    // A string the reader takes whole never ends in a line break for the
    // schema either (Python's `$` matches before one).
    for (const char* key : {"run_id", "client_id", "restore_point"}) {
        CAPTURE(key);
        CHECK(job.at("properties").at(key).at("not").at("pattern") == "\n");
    }
    // W4.11: the connector's name, by the registry's rule.
    const json& type = job.at("properties").at("connector").at("properties").at("type");
    CHECK(type.at("pattern") == "^[a-z0-9_]{1,64}$");
    CHECK(type.at("not").at("pattern") == "\n");
    CHECK(job.at("properties").at("connector").at("additionalProperties") == false);
}

TEST_CASE("jobs: every shared jobs case is judged by the reader as the file says",
          "[service_jobs][schema]")
{
    static const json cases_file =
        json::parse(rp::test::read_shared("testdata/jobs-v1/cases.json"));
    static const json base = json::parse(rp::test::read_shared(
        "testdata/jobs-v1/" + cases_file.at("base").get<std::string>()));
    const json& cases = cases_file.at("cases");
    REQUIRE(cases_file.at("format") == std::string{rp::kJobsFormat});
    // The file can't shrink unnoticed: the Cloud pins the same counts.
    REQUIRE(cases.size() == 84);
    std::size_t valid = 0;
    std::size_t code_refuses = 0;
    for (const json& entry : cases) {
        valid += entry.at("valid").get<bool>() ? 1 : 0;
        code_refuses += entry.value("code_refuses", false) ? 1 : 0;
    }
    REQUIRE(valid == 18);
    REQUIRE(code_refuses == 3);
    // The base is its own canonical form: what the Worker would write.
    REQUIRE(rp::test::read_shared("testdata/jobs-v1/valid.json") == rp::canonical_json(base));

    const std::size_t i = GENERATE(range(std::size_t{0}, std::size_t{72}));
    const json& entry = cases.at(i);
    const std::string name = entry.at("name");
    INFO(name);
    const json document = base.patch(entry.at("patch"));
    const bool schema_valid = entry.at("valid").get<bool>();
    const bool code_refuses_this = entry.value("code_refuses", false);
    REQUIRE((!code_refuses_this || schema_valid));

    const rp::JobsDocument read = rp::parse_jobs(document.dump());
    const bool accepted =
        read.state == rp::JobsState::read &&
        std::ranges::all_of(read.jobs, [](const rp::JobEntry& job) {
            return job.state == rp::JobState::valid;
        });
    CHECK(accepted == (schema_valid && !code_refuses_this));
    if (accepted) {
        for (const rp::JobEntry& job : read.jobs) {
            REQUIRE(job.job.client.has_value());
            CHECK(rp::to_json(*job.job.client) == document.at("jobs").at(job.position - 1).at("client"));
        }
    }
}
