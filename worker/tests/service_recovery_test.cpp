// The service's record of the run it has taken and what follows from it
// (rp/service_recovery.hpp; W4.8, docs/decisions.md 2026-10-08 points 6 to
// 9): running.json's text after each write and its strict reader, the store
// over its file calls, the plan for a folder without a result with the
// result each code gives, the hold's table and when the record goes. Failure
// paths first.

#include "../src/run_pipeline.hpp"

#include <rp/canonical_json.hpp>
#include <rp/connector_registry.hpp>
#include <rp/result_schema.hpp>
#include <rp/service_recovery.hpp>
#include <rp/version.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

using nlohmann::json;
using namespace std::chrono_literals;
using rp::CloseAs;
using rp::RunningRecord;
using TimePoint = std::chrono::system_clock::time_point;

namespace {

// The client a record carries (W4.10): a profile.
rp::ClientProfile short_profile()
{
    rp::ClientProfile profile;
    profile.veeam_org_name = "contoso.onmicrosoft.com";
    profile.graph_tenant_id = "11111111-2222-3333-4444-555555555555";
    profile.graph_client_id = "22222222-3333-4444-5555-666666666666";
    profile.test_mailbox = "restoretest@contoso.onmicrosoft.com";
    profile.test_site_id = "contoso.sharepoint.com,aaaaaaaa-0000-0000-0000-000000000001,"
                           "aaaaaaaa-0000-0000-0000-000000000002";
    profile.test_library_id = "b!library";
    profile.test_onedrive_drive_id = "b!onedrive";
    profile.test_onedrive_folder_id = "01FOLDER";
    return profile;
}

TimePoint at(std::string_view text)
{
    const std::optional<TimePoint> time = rp::record_time(text);
    REQUIRE(time);
    return *time;
}

const char* const kTaken = "2026-10-08T10:00:00.123Z";
const char* const kStarted = "2026-10-08T10:00:02.500Z";
const char* const kRequested = "2026-10-08T10:01:00.000Z";

RunningRecord taken()
{
    return rp::new_run_record("job-0001", std::string{"client-7"}, short_profile(), at(kTaken));
}

rp::RunStarted run_started()
{
    rp::RunStarted started;
    started.run_id = "job-0001";
    started.started_at = kStarted;
    started.restore_point_id = "point-1";
    started.restore_point_time = "2026-10-03T16:16:54.0154727Z";
    started.connector_type = "veeam_m365";
    started.connector_api = "v8";
    return started;
}

RunningRecord started()
{
    return rp::with_run_started(taken(), run_started());
}

// A run that got as far as a restore request, with three sessions of its own.
RunningRecord requested()
{
    RunningRecord record = started();
    for (const char* id : {"a", "b", "c"}) {
        record = rp::with_session(std::move(record), id);
    }
    return rp::with_restore_request(std::move(record), at(kRequested));
}

json as_json(const RunningRecord& record)
{
    return json::parse(rp::record_text(record));
}

// The record's client: the profile's closed object (W4.10).
const std::string kClientText =
    R"("client":{"format":"restoreproof.client-profile.v1",)"
    R"("graph_client_id":"22222222-3333-4444-5555-666666666666",)"
    R"("graph_tenant_id":"11111111-2222-3333-4444-555555555555","test_library_id":"b!library",)"
    R"("test_mailbox":"restoretest@contoso.onmicrosoft.com","test_onedrive_drive_id":"b!onedrive",)"
    R"("test_onedrive_folder_id":"01FOLDER","test_site_id":"contoso.sharepoint.com,)"
    R"(aaaaaaaa-0000-0000-0000-000000000001,aaaaaaaa-0000-0000-0000-000000000002",)"
    R"("veeam_org_name":"contoso.onmicrosoft.com"})";

rp::Evidence two_empty_files(bool screenshots = false)
{
    const std::string hash(64, 'a');
    return {{{"items.csv", hash, 10}, {"veeam-session.log", hash, 0}},
            rp::close_screenshot(screenshots)};
}

struct FakeFiles {
    rp::TrustedFile file{rp::TrustedRead::absent, {}};
    bool write_ok = true;
    bool remove_ok = true;
    bool move_ok = true;
    std::vector<std::string> calls;
    std::string written;
    std::uintmax_t asked_max = 0;

    rp::RecordFiles files()
    {
        rp::RecordFiles out;
        out.read = [this](const std::filesystem::path& path, std::uintmax_t max) {
            calls.push_back("read " + path.generic_string());
            asked_max = max;
            return file;
        };
        out.write = [this](const std::filesystem::path& path, std::string_view text) {
            calls.push_back("write " + path.generic_string());
            written = std::string{text};
            return write_ok;
        };
        out.erase = [this](const std::filesystem::path& path) {
            calls.push_back("remove " + path.generic_string());
            return remove_ok;
        };
        out.move_aside = [this](const std::filesystem::path& from,
                                const std::filesystem::path& to) {
            calls.push_back("move " + from.generic_string() + " " + to.generic_string());
            return move_ok;
        };
        return out;
    }
};

} // namespace

// ---------------------------------------------------------------- the time

TEST_CASE("a record's time is refused in any shape but the result's own", "[service_recovery]")
{
    const std::string text = GENERATE(
        "", "2026-10-08T10:00:00Z", "2026-10-08T10:00:00.123", "2026-10-08 10:00:00.123Z",
        "2026-10-08T10:00:00.12aZ", "2026-10-08T10:00:00,123Z", "2026-10-08T10:00:00.123z",
        "2026-13-08T10:00:00.123Z", "2026-00-08T10:00:00.123Z", "2026-02-30T10:00:00.123Z",
        "2026-10-00T10:00:00.123Z", "2026-10-08T24:00:00.123Z", "2026-10-08T10:60:00.123Z",
        "2026-10-08T10:00:60.123Z", "2026-10-08T10:00:00.1234Z", " 2026-10-08T10:00:00.123Z");
    CAPTURE(text);
    CHECK_FALSE(rp::record_time(text));
}

TEST_CASE("a record's time is written to the millisecond, cut, and reads back",
          "[service_recovery]")
{
    const TimePoint time = at("2026-10-08T23:59:59.999Z");
    CHECK(rp::record_time_text(time) == "2026-10-08T23:59:59.999Z");
    CHECK(rp::record_time_text(time + 900us) == "2026-10-08T23:59:59.999Z");
    CHECK(rp::record_time_text(time + 1ms) == "2026-10-09T00:00:00.000Z");
    CHECK(at("2024-02-29T00:00:00.000Z") - at("2024-02-28T23:59:59.000Z") == 1s);
    CHECK(rp::record_time_text(TimePoint{}) == "1970-01-01T00:00:00.000Z");
}

// --------------------------------------------------------- the strict reader

TEST_CASE("a text that isn't its own canonical form is no record", "[service_recovery]")
{
    const std::string good = rp::record_text(requested());
    REQUIRE(rp::parse_record(good));

    std::string twice = good;
    twice.insert(twice.size() - 1, R"(,"taken_at":"2026-10-08T10:00:00.123Z")");
    std::string reordered = good;
    // "client" moved behind the other keys.
    const std::size_t end_of_client = good.find(R"(,"client_id")");
    reordered = "{" + good.substr(end_of_client + 1, good.size() - end_of_client - 2) + "," +
                good.substr(1, end_of_client - 1) + "}";
    REQUIRE(json::parse(reordered) == json::parse(good));
    // The canonical form has no floating-point number.
    json floated = json::parse(good);
    floated["taken_at"] = 1.5;

    const std::vector<std::pair<std::string, std::string>> rows{
        {"empty", ""},
        {"not JSON", "running"},
        {"cut short", good.substr(0, good.size() - 1)},
        {"an array", "[]"},
        {"null", "null"},
        {"an empty object", "{}"},
        {"pretty-printed", json::parse(good).dump(2)},
        {"a trailing newline", good + "\n"},
        {"a leading blank", " " + good},
        {"a byte order mark", "\xEF\xBB\xBF" + good},
        {"a key twice", twice},
        {"keys in another order", reordered},
        {"a number the form refuses", floated.dump()},
        {"bytes that aren't UTF-8",
         std::string{good}.replace(good.find("\"contoso.onmicrosoft.com\""), 25, "\"\xFF\"")},
    };
    for (const auto& [name, text] : rows) {
        CAPTURE(name);
        CHECK_FALSE(rp::parse_record(text));
    }
}

TEST_CASE("a record nested past the limit is no record, and is never handed to the parser: "
          "50,000 levels in a file under 64 KiB",
          "[service_recovery]")
{
    const std::string good = rp::record_text(requested());
    const std::string key = "\"sessions\":";
    const std::size_t from = good.find(key + "[");
    REQUIRE(from != std::string::npos);
    const std::size_t end = good.find(']', from) + 1;
    const auto nested = [&](std::size_t levels) {
        return std::string{good}.replace(from, end - from,
                                         key + std::string(levels, '[') +
                                             std::string(levels, ']'));
    };
    // Canonicalising it would be a call per level.
    const std::string deep = nested(50'000);
    REQUIRE(deep.size() <= rp::kMaxRecordBytes + 40'000);

    CHECK_FALSE(rp::parse_record(deep));
    CHECK_FALSE(rp::parse_record(nested(rp::kMaxJsonNesting)));
    // What a record itself needs is far below the limit.
    CHECK(rp::json_nesting_depth(good) == 2);
    CHECK(rp::parse_record(good));
}

TEST_CASE("a record with a key missing, one too many or a wrong kind or word is no record",
          "[service_recovery]")
{
    using Change = std::function<void(json&)>;
    const auto set = [](std::string pointer, json value) -> Change {
        return [pointer = std::move(pointer), value = std::move(value)](json& document) {
            document[json::json_pointer(pointer)] = value;
        };
    };
    const auto drop = [](std::string parent, std::string key) -> Change {
        return [parent = std::move(parent), key = std::move(key)](json& document) {
            document[json::json_pointer(parent)].erase(key);
        };
    };
    const auto both = [](Change first, Change second) -> Change {
        return [first = std::move(first), second = std::move(second)](json& document) {
            first(document);
            second(document);
        };
    };
    const std::string long129(129, 'x');
    const std::string long1025(1025, 'x');

    std::vector<std::pair<std::string, Change>> rows;
    for (const char* key :
         {"client", "client_id", "close_as", "close_detail", "connector", "format", "kind",
          "restore_point", "restore_requested", "restore_requested_at", "run_id", "sessions",
          "started_at", "taken_at"}) {
        rows.emplace_back(std::string{"no "} + key, drop("", key));
        // Fourteen keys still, one of them not the record's.
        rows.emplace_back(std::string{"another key for "} + key,
                          both(drop("", key), set("/zz", nullptr)));
    }
    const std::vector<std::pair<std::string, Change>> more{
        {"a fifteenth key", set("/zz", 1)},
        {"another format", set("/format", "restoreproof.running.v2")},
        {"format not a string", set("/format", 1)},
        {"an unknown kind", set("/kind", "other")},
        {"kind null", set("/kind", nullptr)},
        {"run_id with a colon", set("/run_id", "a:b")},
        {"run_id a device", set("/run_id", "PRN")},
        {"run_id a number", set("/run_id", 5)},
        // The client is a profile by the profile's rules (W4.10); null only
        // for a job_invalid record.
        {"client null for a run", set("/client", nullptr)},
        {"client without graph_tenant_id", drop("/client", "graph_tenant_id")},
        {"client with a tenth key", set("/client/zz", 1)},
        {"client with a client_id", set("/client/client_id", "client-7")},
        {"client as W4.8's result object",
         set("/client", json{{"client_id", nullptr},
                             {"tenant_id", "T"},
                             {"veeam_org_name", "O"},
                             {"targets", json::object()}})},
        {"graph_tenant_id a number", set("/client/graph_tenant_id", 1)},
        {"graph_tenant_id not a GUID", set("/client/graph_tenant_id", "T")},
        {"veeam_org_name over the schema's length", set("/client/veeam_org_name", long1025)},
        {"veeam_org_name null", set("/client/veeam_org_name", nullptr)},
        {"client format another document's", set("/client/format", "restoreproof.jobs.v1")},
        {"test_mailbox another user", set("/client/test_mailbox", "alice@contoso.onmicrosoft.com")},
        {"test_site_id a number", set("/client/test_site_id", 5)},
        {"test_library_id over its length",
         set("/client/test_library_id", "b!" + std::string(201, 'x'))},
        {"test_onedrive_drive_id null", set("/client/test_onedrive_drive_id", nullptr)},
        {"test_onedrive_folder_id an array", set("/client/test_onedrive_folder_id", json::array())},
        {"client_id empty", set("/client_id", "")},
        {"client_id of 129 characters", set("/client_id", long129)},
        {"client_id with a tab", set("/client_id", "a\tb")},
        {"client_id not ASCII", set("/client_id", "caf\xC3\xA9")},
        {"client_id a number", set("/client_id", 5)},
        {"an unknown close_as", set("/close_as", "interrupted")},
        {"close_as a number", set("/close_as", 1)},
        {"a folder's word without close_as that isn't changed",
         set("/close_detail", "not_signed")},
        {"an ending without close_as", set("/close_detail", "pass")},
        {"close_detail a number", set("/close_detail", 1)},
        {"internal without its word", set("/close_as", "internal")},
        {"internal with another word",
         both(set("/close_as", "internal"), set("/close_detail", "vault"))},
        {"result_invalid with a code the table doesn't hold",
         both(set("/close_as", "result_invalid"), set("/close_detail", "error teapot"))},
        {"result_invalid with a word that isn't an ending",
         both(set("/close_as", "result_invalid"), set("/close_detail", "errors"))},
        {"result_invalid with a code after pass",
         both(set("/close_as", "result_invalid"), set("/close_detail", "pass config"))},
        {"result_invalid with error and a blank",
         both(set("/close_as", "result_invalid"), set("/close_detail", "error "))},
        {"result_invalid with changed and no ending",
         both(set("/close_as", "result_invalid"), set("/close_detail", "; changed"))},
        {"result_invalid with changed alone",
         both(set("/close_as", "result_invalid"), set("/close_detail", "changed"))},
        {"result_invalid with changed twice",
         both(set("/close_as", "result_invalid"), set("/close_detail", "pass; changed; changed"))},
        {"result_invalid with changed after no ending",
         both(set("/close_as", "result_invalid"), set("/close_detail", "errors; changed"))},
        {"job_invalid for a run",
         both(set("/close_as", "job_invalid"), set("/close_detail", "sample_mail"))},
        {"kind job_invalid without close_as", set("/kind", "job_invalid")},
        {"kind job_invalid closed as internal",
         both(set("/kind", "job_invalid"),
              both(set("/close_as", "internal"), set("/close_detail", "changed")))},
        {"job_invalid without its key",
         both(set("/kind", "job_invalid"), set("/close_as", "job_invalid"))},
        {"job_invalid with a key in capitals",
         both(set("/kind", "job_invalid"),
              both(set("/close_as", "job_invalid"), set("/close_detail", "Sample_mail")))},
        {"job_invalid with an empty key",
         both(set("/kind", "job_invalid"),
              both(set("/close_as", "job_invalid"), set("/close_detail", "")))},
        {"job_invalid with a key of 33 characters",
         both(set("/kind", "job_invalid"),
              both(set("/close_as", "job_invalid"),
                   set("/close_detail", std::string(33, 'k'))))},
        {"connector a number", set("/connector", 5)},
        {"another connector", set("/connector/type", "other")},
        {"connector type a number", set("/connector/type", 5)},
        {"connector without api", drop("/connector", "api")},
        {"connector with a third key", set("/connector/zz", 1)},
        {"connector api of 65 characters", set("/connector/api", std::string(65, 'v'))},
        {"connector api null", set("/connector/api", nullptr)},
        {"restore_point a string", set("/restore_point", "point-1")},
        {"restore_point without id", drop("/restore_point", "id")},
        {"restore_point with a third key", set("/restore_point/backup_time", nullptr)},
        {"restore_point id over the schema's length", set("/restore_point/id", long1025)},
        {"restore_point backup_time_raw a number", set("/restore_point/backup_time_raw", 5)},
        {"restore_point backup_time_raw over the schema's length",
         set("/restore_point/backup_time_raw", long1025)},
        {"restore_requested a word", set("/restore_requested", "yes")},
        {"restore_requested null", set("/restore_requested", nullptr)},
        {"requested without its time", set("/restore_requested_at", nullptr)},
        {"a request's time without a request", set("/restore_requested", false)},
        {"restore_requested_at no time", set("/restore_requested_at", "2026-13-01T00:00:00.000Z")},
        {"restore_requested_at a number", set("/restore_requested_at", 5)},
        {"sessions null", set("/sessions", nullptr)},
        {"sessions an object", set("/sessions", json::object())},
        {"a session a number", set("/sessions/1", 5)},
        {"a session empty", set("/sessions/0", "")},
        {"a session with a line break", set("/sessions/2", "a\nb")},
        {"a session of 129 characters", set("/sessions/0", long129)},
        {"started_at to the second", set("/started_at", "2026-10-08T10:00:02Z")},
        {"started_at a number", set("/started_at", 5)},
        {"taken_at null", set("/taken_at", nullptr)},
        {"taken_at no time", set("/taken_at", "yesterday")},
    };
    rows.insert(rows.end(), more.begin(), more.end());

    const json good = as_json(requested());
    for (const auto& [name, change] : rows) {
        CAPTURE(name);
        json document = good;
        change(document);
        REQUIRE(document != good);
        CHECK_FALSE(rp::parse_record(rp::canonical_json(document)));
    }
}

TEST_CASE("a record reads with each word and each null it may hold", "[service_recovery]")
{
    using Change = std::function<void(RunningRecord&)>;
    const auto closed = [](CloseAs close_as, std::optional<std::string> detail) -> Change {
        return [=](RunningRecord& record) {
            record = rp::with_close(std::move(record), close_as, detail);
        };
    };
    const std::vector<std::pair<std::string, Change>> rows{
        {"as it is", [](RunningRecord&) {}},
        {"just taken", [](RunningRecord& record) { record = taken(); }},
        {"just started", [](RunningRecord& record) { record = started(); }},
        {"no client_id", [](RunningRecord& record) { record.client_id.reset(); }},
        {"client_id of 128 characters",
         [](RunningRecord& record) { record.client_id = std::string(128, '~'); }},
        {"an empty api", [](RunningRecord& record) { record.connector->version.clear(); }},
        {"a tenant's name that isn't ASCII",
         [](RunningRecord& record) { record.client->veeam_org_name = "caf\xC3\xA9"; }},
        {"job_invalid without a client, a profile that couldn't be read",
         [](RunningRecord& record) {
             record = rp::new_job_invalid_record("job-0002", std::string{"c"}, std::nullopt,
                                                 at(kTaken), "client.test_mailbox");
         }},
        {"interrupted, a text file changed at the close",
         [](RunningRecord& record) { record.close_detail = "changed"; }},
        {"result_invalid after pass, a text file changed at the close",
         closed(CloseAs::result_invalid, "pass; changed")},
        {"result_invalid after error graph_transient, a text file changed at the close",
         closed(CloseAs::result_invalid, "error graph_transient; changed")},
        {"internal not_written", closed(CloseAs::internal, "not_written")},
        {"internal changed", closed(CloseAs::internal, "changed")},
        {"internal holds_secret", closed(CloseAs::internal, "holds_secret")},
        {"internal not_signed", closed(CloseAs::internal, "not_signed")},
        {"internal invalid", closed(CloseAs::internal, "invalid")},
        {"result_invalid, the ending not known", closed(CloseAs::result_invalid, std::nullopt)},
        {"result_invalid after pass", closed(CloseAs::result_invalid, "pass")},
        {"result_invalid after fail", closed(CloseAs::result_invalid, "fail")},
        {"result_invalid after error", closed(CloseAs::result_invalid, "error")},
        {"result_invalid after error graph_transient",
         closed(CloseAs::result_invalid, "error graph_transient")},
        {"job_invalid sample_mail",
         [](RunningRecord& record) {
             record = rp::new_job_invalid_record("job-0002", std::nullopt, short_profile(),
                                                 at(kTaken), "sample_mail");
         }},
        {"job_invalid unknown key",
         [](RunningRecord& record) {
             record = rp::new_job_invalid_record("job-0002", std::string{"c"}, short_profile(),
                                                 at(kTaken), "unknown key");
         }},
    };
    for (const auto& [name, change] : rows) {
        CAPTURE(name);
        RunningRecord record = requested();
        change(record);
        const std::optional<RunningRecord> read = rp::parse_record(rp::record_text(record));
        REQUIRE(read);
        CHECK(*read == record);
        CHECK(rp::record_text(*read) == rp::record_text(record));
    }
}

TEST_CASE("two records differ when any one field does", "[service_recovery]")
{
    using Change = std::function<void(RunningRecord&)>;
    const std::vector<Change> rows{
        [](RunningRecord& r) { r.client->test_mailbox = "restoretest@other.example"; },
        [](RunningRecord& r) { r.client.reset(); },
        [](RunningRecord& r) { r.client_id = "other"; },
        [](RunningRecord& r) { r.close_as = CloseAs::internal; },
        [](RunningRecord& r) { r.close_detail = "changed"; },
        [](RunningRecord& r) { r.connector.reset(); },
        [](RunningRecord& r) { r.connector->name = "other"; },
        [](RunningRecord& r) { r.connector->version = "v9"; },
        [](RunningRecord& r) { r.kind = rp::RecordKind::job_invalid; },
        [](RunningRecord& r) { r.restore_point->id = "other"; },
        [](RunningRecord& r) { r.restore_requested = false; },
        [](RunningRecord& r) { r.restore_requested_at.reset(); },
        [](RunningRecord& r) { r.run_id = "other"; },
        [](RunningRecord& r) { r.sessions.pop_back(); },
        [](RunningRecord& r) { r.started_at.reset(); },
        [](RunningRecord& r) { r.taken_at = kStarted; },
    };
    for (std::size_t i = 0; i < rows.size(); ++i) {
        CAPTURE(i);
        RunningRecord changed = requested();
        rows[i](changed);
        CHECK_FALSE(changed == requested());
    }
    CHECK(requested() == requested());
}

// ------------------------------------------------- the text after each write

TEST_CASE("the record's canonical text after each of its writes", "[service_recovery]")
{
    // (a) Before the pipeline is called.
    RunningRecord record = taken();
    CHECK(rp::record_text(record) ==
          "{" + kClientText +
              R"(,"client_id":"client-7","close_as":null,"close_detail":null,"connector":null,)"
              R"("format":"restoreproof.running.v1","kind":"run","restore_point":null,)"
              R"("restore_requested":false,"restore_requested_at":null,"run_id":"job-0001",)"
              R"("sessions":[],"started_at":null,"taken_at":"2026-10-08T10:00:00.123Z"})");

    // (b) Right after the run line.
    record = rp::with_run_started(std::move(record), run_started());
    CHECK(rp::record_text(record) ==
          "{" + kClientText +
              R"(,"client_id":"client-7","close_as":null,"close_detail":null,)"
              R"("connector":{"api":"v8","type":"veeam_m365"},)"
              R"("format":"restoreproof.running.v1","kind":"run",)"
              R"("restore_point":{"backup_time_raw":"2026-10-03T16:16:54.0154727Z","id":"point-1"},)"
              R"("restore_requested":false,"restore_requested_at":null,"run_id":"job-0001",)"
              R"("sessions":[],"started_at":"2026-10-08T10:00:02.500Z",)"
              R"("taken_at":"2026-10-08T10:00:00.123Z"})");

    // (c) At every session opened: in the order opened, each once.
    record = rp::with_session(std::move(record), "s-2");
    record = rp::with_session(std::move(record), "s-1");
    record = rp::with_session(std::move(record), "s-2");
    CHECK(as_json(record)["sessions"] == json::array({"s-2", "s-1"}));

    // (d) Before every restore request: the time of the last one.
    record = rp::with_restore_request(std::move(record), at(kRequested));
    CHECK(as_json(record)["restore_requested"] == true);
    CHECK(as_json(record)["restore_requested_at"] == kRequested);
    record = rp::with_restore_request(std::move(record), at(kRequested) + 7s + 900us);
    CHECK(as_json(record)["restore_requested_at"] == "2026-10-08T10:01:07.000Z");

    // (e) After a run that left its folder without a result.
    record = rp::with_close(std::move(record), CloseAs::internal, "not_signed");
    CHECK(rp::record_text(record) ==
          "{" + kClientText +
              R"(,"client_id":"client-7","close_as":"internal","close_detail":"not_signed",)"
              R"("connector":{"api":"v8","type":"veeam_m365"},)"
              R"("format":"restoreproof.running.v1","kind":"run",)"
              R"("restore_point":{"backup_time_raw":"2026-10-03T16:16:54.0154727Z","id":"point-1"},)"
              R"("restore_requested":true,"restore_requested_at":"2026-10-08T10:01:07.000Z",)"
              R"("run_id":"job-0001","sessions":["s-2","s-1"],)"
              R"("started_at":"2026-10-08T10:00:02.500Z","taken_at":"2026-10-08T10:00:00.123Z"})");
}

TEST_CASE("a run whose clock failed at its start is recorded without started_at",
          "[service_recovery]")
{
    rp::RunStarted without = run_started();
    without.started_at.reset();
    const RunningRecord record = rp::with_run_started(taken(), without);
    CHECK_FALSE(record.started_at);
    CHECK(as_json(record)["started_at"].is_null());
    CHECK(as_json(record)["connector"] == json{{"type", "veeam_m365"}, {"api", "v8"}});
}

TEST_CASE("a job that is no job is recorded with its key from the first write",
          "[service_recovery]")
{
    const RunningRecord record = rp::new_job_invalid_record("job-0002", std::nullopt,
                                                            short_profile(), at(kTaken),
                                                            "restore_point");
    CHECK(rp::record_text(record) ==
          "{" + kClientText +
              R"(,"client_id":null,"close_as":"job_invalid","close_detail":"restore_point",)"
              R"("connector":null,"format":"restoreproof.running.v1","kind":"job_invalid",)"
              R"("restore_point":null,"restore_requested":false,"restore_requested_at":null,)"
              R"("run_id":"job-0002","sessions":[],"started_at":null,)"
              R"("taken_at":"2026-10-08T10:00:00.123Z"})");
}

// W4.10 point 4: the record carries the job's profile whole, and the result
// written afterwards takes its client from it with the job's client_id.
TEST_CASE("the record's client is the job's profile, and the close's result is made from it",
          "[service_recovery]")
{
    const RunningRecord record =
        rp::new_run_record("job-0001", std::string{"client-7"}, short_profile(), at(kTaken));
    CHECK(as_json(record)["client"] == rp::to_json(short_profile()));

    const rp::ClosePlan plan = rp::plan_close(record, {});
    const auto built = rp::build_close_result(plan, two_empty_files());
    REQUIRE(std::holds_alternative<rp::BuiltResult>(built));
    CHECK(std::get<rp::BuiltResult>(built).document["client"] ==
          json{{"client_id", "client-7"},
               {"tenant_id", "11111111-2222-3333-4444-555555555555"},
               {"veeam_org_name", "contoso.onmicrosoft.com"},
               {"targets",
                {{"mailbox", "restoretest@contoso.onmicrosoft.com"},
                 {"site_id", "contoso.sharepoint.com,aaaaaaaa-0000-0000-0000-000000000001,"
                             "aaaaaaaa-0000-0000-0000-000000000002"},
                 {"library_id", "b!library"},
                 {"onedrive_drive_id", "b!onedrive"},
                 {"onedrive_folder_id", "01FOLDER"}}}});

    // A job whose profile couldn't be read: the empty strings the schema
    // allows, beside the job's client_id.
    const RunningRecord no_profile = rp::new_job_invalid_record(
        "job-0002", std::string{"client-8"}, std::nullopt, at(kTaken), "client");
    CHECK(as_json(no_profile)["client"].is_null());
    const auto closed = rp::build_close_result(rp::plan_close(no_profile, {}), two_empty_files());
    REQUIRE(std::holds_alternative<rp::BuiltResult>(closed));
    const json& client = std::get<rp::BuiltResult>(closed).document["client"];
    CHECK(client["client_id"] == "client-8");
    CHECK(client["tenant_id"] == "");
    CHECK(client["targets"]["mailbox"] == "");
}

TEST_CASE("a record is read only with a client the profile's rules take, and a run record "
          "never without one",
          "[service_recovery]")
{
    const RunningRecord run = started();
    json document = as_json(run);
    SECTION("a run record with client null")
    {
        document["client"] = nullptr;
        CHECK_FALSE(rp::parse_record(rp::canonical_json(document)));
    }
    SECTION("a client that is the result's object, as W4.8 wrote it")
    {
        document["client"] = json{{"client_id", nullptr},
                                  {"tenant_id", "T"},
                                  {"veeam_org_name", "O"},
                                  {"targets",
                                   {{"mailbox", "M"},
                                    {"site_id", "S"},
                                    {"library_id", "L"},
                                    {"onedrive_drive_id", "D"},
                                    {"onedrive_folder_id", "F"}}}};
        CHECK_FALSE(rp::parse_record(rp::canonical_json(document)));
    }
    SECTION("a client with a key at fault")
    {
        document["client"]["test_mailbox"] = "alice@contoso.onmicrosoft.com";
        CHECK_FALSE(rp::parse_record(rp::canonical_json(document)));
    }
    SECTION("a job_invalid record with client null is read")
    {
        const RunningRecord no_profile = rp::new_job_invalid_record(
            "job-0002", std::nullopt, std::nullopt, at(kTaken), "client");
        const std::optional<RunningRecord> read = rp::parse_record(rp::record_text(no_profile));
        REQUIRE(read);
        CHECK_FALSE(read->client);
        CHECK(*read == no_profile);
    }
    SECTION("the key words a J3 fault may be")
    {
        for (const char* key : {"client", "client.test_mailbox", "client.test_onedrive_folder_id",
                                "unknown key", "sample_mail"}) {
            CAPTURE(key);
            const RunningRecord made =
                rp::new_job_invalid_record("job-0002", std::nullopt, short_profile(), at(kTaken), key);
            CHECK(rp::parse_record(rp::record_text(made)));
        }
    }
}

TEST_CASE("how a run had ended, as close_detail keeps it", "[service_recovery]")
{
    using rp::verification::RunStatus;
    CHECK(rp::ended_detail(RunStatus::pass, "") == "pass");
    CHECK(rp::ended_detail(RunStatus::pass, "config") == "pass");
    CHECK(rp::ended_detail(RunStatus::fail, "") == "fail");
    CHECK(rp::ended_detail(RunStatus::error, "backup_transient") == "error backup_transient");
    CHECK(rp::ended_detail(RunStatus::error, "") == "error");
    CHECK(rp::ended_detail(RunStatus::error, "teapot") == "error");
    CHECK(rp::ended_detail(static_cast<RunStatus>(9), "config") == "error config");

    CHECK(rp::to_string(rp::RecordKind::run) == "run");
    CHECK(rp::to_string(rp::RecordKind::job_invalid) == "job_invalid");
    CHECK(rp::to_string(CloseAs::result_invalid) == "result_invalid");
    CHECK(rp::to_string(CloseAs::internal) == "internal");
    CHECK(rp::to_string(CloseAs::job_invalid) == "job_invalid");
}

// ----------------------------------------------------------------- the store

TEST_CASE("the store says what is at the record's path, and never reads an untrusted file",
          "[service_recovery]")
{
    struct Row {
        rp::TrustedRead read;
        std::string bytes;
        rp::RecordState state;
    };
    const std::string good = rp::record_text(requested());
    const Row row = GENERATE_COPY(
        Row{rp::TrustedRead::absent, "", rp::RecordState::none},
        Row{rp::TrustedRead::not_trusted, "", rp::RecordState::not_trusted},
        Row{rp::TrustedRead::unreadable, "", rp::RecordState::unreadable},
        Row{rp::TrustedRead::too_large, "", rp::RecordState::not_record},
        Row{rp::TrustedRead::read, "", rp::RecordState::not_record},
        Row{rp::TrustedRead::read, good + "\n", rp::RecordState::not_record},
        Row{rp::TrustedRead::read, good, rp::RecordState::record});
    CAPTURE(static_cast<int>(row.read), row.bytes.size());

    FakeFiles fake;
    fake.file = {row.read, row.bytes};
    const rp::RecordStore store{"state/running.json", fake.files()};
    const rp::RecordRead read = store.read();

    CHECK(read.state == row.state);
    CHECK(read.record.has_value() == (row.state == rp::RecordState::record));
    if (read.record) {
        CHECK(*read.record == requested());
    }
    CHECK(fake.calls == std::vector<std::string>{"read state/running.json"});
    CHECK(fake.asked_max == rp::kMaxRecordBytes);
}

TEST_CASE("the store writes nothing that wouldn't read back as a record", "[service_recovery]")
{
    FakeFiles fake;
    const rp::RecordStore store{"state/running.json", fake.files()};

    SECTION("a string that isn't UTF-8")
    {
        RunningRecord record = requested();
        record.client->veeam_org_name = "\xFF";
        CHECK_FALSE(store.write(record));
    }
    SECTION("a session ID that isn't one")
    {
        CHECK_FALSE(store.write(rp::with_session(requested(), "a\nb")));
    }
    SECTION("a close without its word")
    {
        CHECK_FALSE(store.write(rp::with_close(requested(), CloseAs::internal, std::nullopt)));
    }
    SECTION("more sessions than a record's size takes")
    {
        RunningRecord record = requested();
        for (int i = 0; i < 600; ++i) {
            record = rp::with_session(std::move(record), std::string(120, 's') + std::to_string(i));
        }
        REQUIRE(rp::record_text(record).size() > rp::kMaxRecordBytes);
        REQUIRE(rp::parse_record(rp::record_text(record)));
        CHECK_FALSE(store.write(record));
    }
    CHECK(fake.calls.empty());
}

TEST_CASE("the store hands the writer the canonical text and answers as it does",
          "[service_recovery]")
{
    const bool ok = GENERATE(false, true);
    FakeFiles fake;
    fake.write_ok = ok;
    const rp::RecordStore store{"state/running.json", fake.files()};

    CHECK(store.write(requested()) == ok);
    CHECK(fake.calls == std::vector<std::string>{"write state/running.json"});
    CHECK(fake.written == rp::record_text(requested()));
}

TEST_CASE("the store removes the record and moves it aside beside itself", "[service_recovery]")
{
    const bool ok = GENERATE(false, true);
    FakeFiles fake;
    fake.remove_ok = ok;
    fake.move_ok = ok;
    const rp::RecordStore store{"state/running.json", fake.files()};

    CHECK(store.file() == std::filesystem::path{"state/running.json"});
    CHECK(store.unread_file() == std::filesystem::path{"state"} / "running.json.unread");
    CHECK(store.erase() == ok);
    CHECK(store.move_aside() == ok);
    CHECK(fake.calls ==
          std::vector<std::string>{"remove state/running.json",
                                   "move state/running.json state/running.json.unread"});
}

// ------------------------------------------------------------ the close plan

namespace {

struct FolderRow {
    std::string name;
    rp::FolderContents folder;
    rp::CloseAction action;
    bool make_folder;
    std::vector<std::string> remove;
    bool remove_temp_files;
};

std::vector<FolderRow> folder_rows()
{
    using rp::CloseAction;
    const auto holding = [](bool items, bool log, bool signature, bool timestamp,
                            bool screenshot, bool temp, bool result = false) {
        rp::FolderContents folder;
        folder.exists = true;
        folder.items_csv = items;
        folder.session_log = log;
        folder.signature = signature;
        folder.timestamp = timestamp;
        folder.screenshot = screenshot;
        folder.temp_files = temp;
        folder.result = result;
        return folder;
    };
    return {
        {"not there", {}, CloseAction::close, true, {}, false},
        {"empty", holding(false, false, false, false, false, false), CloseAction::close, false,
         {}, false},
        {"items.csv alone", holding(true, false, false, false, false, false), CloseAction::close,
         false, {}, false},
        {"the two text files", holding(true, true, false, false, false, false),
         CloseAction::close, false, {}, false},
        {"a temp file", holding(true, false, false, false, false, true), CloseAction::close,
         false, {}, true},
        {"signature.json alone", holding(true, true, true, false, false, false),
         CloseAction::close, false, {"signature.json"}, false},
        {"signature.json and timestamp.tst", holding(true, true, true, true, false, false),
         CloseAction::close, false, {"signature.json", "timestamp.tst"}, false},
        {"a screenshot", holding(true, true, false, false, true, false), CloseAction::close,
         false, {"screenshot.png"}, false},
        {"everything a kill can leave", holding(true, true, true, true, true, true),
         CloseAction::close, false, {"signature.json", "timestamp.tst", "screenshot.png"}, true},
        {"complete", holding(true, true, true, true, false, false, true),
         CloseAction::queue_only, false, {}, false},
        {"complete, with a temp file beside", holding(true, true, true, false, true, true, true),
         CloseAction::queue_only, false, {}, false},
    };
}

} // namespace

TEST_CASE("what closing a folder means, by what it holds", "[service_recovery]")
{
    const FolderRow row = GENERATE(from_range(folder_rows()));
    CAPTURE(row.name);

    const rp::ClosePlan plan = rp::plan_close(requested(), row.folder);

    CHECK(plan.action == row.action);
    CHECK(plan.run_id == "job-0001");
    CHECK(plan.make_folder == row.make_folder);
    CHECK(plan.remove == row.remove);
    CHECK(plan.remove_temp_files == row.remove_temp_files);
    CHECK(plan.removes() == (!row.remove.empty() || row.remove_temp_files));
    // Kept as they are: the run only ever wrote each whole.
    CHECK_FALSE(plan.replace_text_files);
    if (row.action == rp::CloseAction::close) {
        CHECK(plan.code == "interrupted");
    }
}

namespace {

struct CodeRow {
    std::string name;
    RunningRecord record;
    std::string code;
    std::string message;
    bool restore_sent;
    bool replace_text_files;
};

std::vector<CodeRow> code_rows()
{
    const RunningRecord not_requested = rp::with_session(started(), "a");
    const auto closed = [](RunningRecord record, CloseAs close_as,
                           std::optional<std::string> detail) {
        return rp::with_close(std::move(record), close_as, std::move(detail));
    };
    const std::string internal = "the run ended without a result the Worker could write; this "
                                 "result was written afterwards";
    const std::string invalid = "the result isn't valid restoreproof.result.v1; the run itself "
                                "ended ";
    std::vector<CodeRow> rows{
        {"killed before its run line", taken(), "interrupted",
         "the run was interrupted before its result was written; no restore request had been "
         "sent",
         false, false},
        {"killed before a restore request", not_requested, "interrupted",
         "the run was interrupted before its result was written; no restore request had been "
         "sent",
         false, false},
        {"killed after a restore request", requested(), "interrupted",
         "the run was interrupted before its result was written; a restore request may have "
         "been sent, so items may be in the restore targets",
         true, false},
        {"result_invalid after pass", closed(requested(), CloseAs::result_invalid, "pass"),
         "result_invalid", invalid + "pass", true, false},
        {"result_invalid after fail", closed(requested(), CloseAs::result_invalid, "fail"),
         "result_invalid", invalid + "fail", true, false},
        {"result_invalid after error graph_auth",
         closed(not_requested, CloseAs::result_invalid, "error graph_auth"), "result_invalid",
         invalid + "error graph_auth", false, false},
        {"result_invalid after error", closed(requested(), CloseAs::result_invalid, "error"),
         "result_invalid", invalid + "error", true, false},
        {"result_invalid, the ending not known",
         closed(requested(), CloseAs::result_invalid, std::nullopt), "result_invalid",
         invalid + "error", true, false},
        {"job_invalid",
         rp::new_job_invalid_record("job-0001", std::string{"client-7"}, short_profile(),
                                    at(kTaken), "sample_mail"),
         "job_invalid", "the job isn't a valid job (sample_mail); nothing was done", false,
         // Nothing in the folder of a job that is no job is a run's evidence.
         true},
        {"interrupted, a text file changed at an earlier close",
         rp::with_changed_text_files(requested()), "interrupted",
         "the run was interrupted before its result was written; a restore request may have "
         "been sent, so items may be in the restore targets",
         true, true},
        {"result_invalid after fail, a text file changed at an earlier close",
         rp::with_changed_text_files(closed(requested(), CloseAs::result_invalid, "fail")),
         "result_invalid", invalid + "fail", true, true},
        {"result_invalid after error graph_auth, a text file changed at an earlier close",
         rp::with_changed_text_files(
             closed(not_requested, CloseAs::result_invalid, "error graph_auth")),
         "result_invalid", invalid + "error graph_auth", false, true},
        {"result_invalid, the ending not known, a text file changed at an earlier close",
         rp::with_changed_text_files(closed(requested(), CloseAs::result_invalid, std::nullopt)),
         "result_invalid", invalid + "error", true, true},
        {"internal not_signed, a text file changed at an earlier close",
         rp::with_changed_text_files(closed(requested(), CloseAs::internal, "not_signed")),
         "internal", internal, true, true},
    };
    for (const char* word : {"not_written", "changed", "holds_secret", "not_signed", "invalid"}) {
        const bool changed = std::string_view{word} == "changed";
        rows.push_back({std::string{"internal "} + word,
                        closed(requested(), CloseAs::internal, word), "internal", internal, true,
                        changed});
        rows.push_back({std::string{"internal "} + word + ", no restore requested",
                        closed(not_requested, CloseAs::internal, word), "internal", internal,
                        false, changed});
    }
    return rows;
}

} // namespace

TEST_CASE("the result written afterwards, for each code, is valid restoreproof.result.v1",
          "[service_recovery]")
{
    const CodeRow row = GENERATE(from_range(code_rows()));
    const bool screenshots = GENERATE(false, true);
    CAPTURE(row.name, screenshots);

    const rp::ClosePlan plan = rp::plan_close(row.record, {});
    REQUIRE(plan.action == rp::CloseAction::close);
    CHECK(plan.code == row.code);
    CHECK(plan.replace_text_files == row.replace_text_files);

    const auto built = rp::build_close_result(plan, two_empty_files(screenshots));
    REQUIRE(std::holds_alternative<rp::BuiltResult>(built));
    const rp::BuiltResult& result = std::get<rp::BuiltResult>(built);
    const rp::ResultValidation validation = rp::validate_result(result.document);
    CAPTURE(validation.first_pointer);
    REQUIRE(validation.valid);
    CHECK(rp::canonical_json(result.document) == result.canonical);

    const json& document = result.document;
    CHECK(document["status"] ==
          json{{"status", "error"},
               {"error_code", row.code},
               {"message", row.message},
               {"restore_sent", row.restore_sent},
               {"counts", {{"items", 0}, {"verified", 0}, {"failed", 0}, {"unchecked", 0}}},
               {"verified", {{"manifest", 0}, {"fields", 0}, {"metadata", 0}}},
               {"failed_items", json::array()},
               {"unchecked_items", json::array()},
               {"warnings", json::array()}});
    CHECK(document["run_id"] == "job-0001");
    CHECK(document["worker_version"] == std::string{rp::version()});
    CHECK(document["ended_at"].is_null());
    for (const char* step : {"sample", "expected", "restore", "check", "cleanup"}) {
        CAPTURE(step);
        CHECK(document[step].is_null());
    }
    for (const auto& span : document["timings"]["spans"]) {
        CHECK(span.is_null());
    }
    CHECK(document["timings"]["spans"].size() == 11);
    // The result's client: the record's profile cut to the result's object,
    // with the job's client_id (W4.10).
    REQUIRE(row.record.client);
    const rp::ClientProfile& profile = *row.record.client;
    CHECK(document["client"] ==
          json{{"client_id", row.record.client_id ? json(*row.record.client_id) : json()},
               {"tenant_id", profile.graph_tenant_id},
               {"veeam_org_name", profile.veeam_org_name},
               {"targets",
                {{"mailbox", profile.test_mailbox},
                 {"site_id", profile.test_site_id},
                 {"library_id", profile.test_library_id},
                 {"onedrive_drive_id", profile.test_onedrive_drive_id},
                 {"onedrive_folder_id", profile.test_onedrive_folder_id}}}});
    CHECK(document["attachments"].size() == 2);
    CHECK(document["screenshot"] ==
          json{{"state", "unavailable"}, {"reason", screenshots ? "no_page" : "disabled"}});

    // What the record knows, else the empty forms the pipeline writes.
    if (row.record.started_at) {
        CHECK(document["started_at"] == kStarted);
        CHECK(document["connector"] == json{{"type", "veeam_m365"}, {"api", "v8"}});
        CHECK(document["restore_point"] ==
              json{{"id", "point-1"},
                   {"backup_time_raw", "2026-10-03T16:16:54.0154727Z"},
                   {"backup_time", "2026-10-03T16:16:54Z"}});
    } else {
        CHECK(document["started_at"].is_null());
        CHECK(document["connector"] == json{{"type", "veeam_m365"}, {"api", ""}});
        CHECK(document["restore_point"] ==
              json{{"id", ""}, {"backup_time_raw", ""}, {"backup_time", nullptr}});
    }
}

TEST_CASE("a close that found a text file changed is on record without changing what the run "
          "is closed as",
          "[service_recovery]")
{
    struct Row {
        std::optional<CloseAs> close_as;
        std::optional<std::string> detail;
        std::optional<std::string> afterwards;
    };
    const Row row = GENERATE(
        Row{std::nullopt, std::nullopt, "changed"},
        Row{CloseAs::internal, "not_signed", "changed"},
        Row{CloseAs::internal, "changed", "changed"},
        Row{CloseAs::result_invalid, "pass", "pass; changed"},
        Row{CloseAs::result_invalid, "error graph", "error graph; changed"},
        Row{CloseAs::result_invalid, std::nullopt, "error; changed"});
    CAPTURE(row.detail, row.afterwards);
    RunningRecord record = requested();
    record.close_as = row.close_as;
    record.close_detail = row.detail;

    const RunningRecord next = rp::with_changed_text_files(record);

    CHECK(next.close_as == row.close_as);
    CHECK(next.close_detail == row.afterwards);
    // Nothing else, a record that reads, and the same when written twice.
    RunningRecord same = next;
    same.close_detail = record.close_detail;
    CHECK(same == record);
    CHECK(rp::parse_record(rp::record_text(next)) == next);
    CHECK(rp::with_changed_text_files(next) == next);
    CHECK(rp::plan_close(next, {}).replace_text_files);
    CHECK(rp::plan_close(next, {}).code == rp::plan_close(record, {}).code);
}

TEST_CASE("a job that is no job has nothing to put on record for changed text files",
          "[service_recovery]")
{
    const RunningRecord record = rp::new_job_invalid_record(
        "job-0001", std::string{"client-7"}, short_profile(), at(kTaken), "sample_mail");
    CHECK(rp::with_changed_text_files(record) == record);
}

TEST_CASE("a plan the schema doesn't take gives no result", "[service_recovery]")
{
    rp::ClosePlan plan = rp::plan_close(requested(), {});
    plan.connector.name = "other";
    const auto built = rp::build_close_result(plan, two_empty_files());
    REQUIRE(std::holds_alternative<rp::ResultError>(built));
    CHECK(std::get<rp::ResultError>(built).cause == rp::ResultFailure::schema);
}

// ------------------------------------------------------------- closing a run

namespace {

struct FakeClose {
    rp::FolderContents folder;
    bool make_ok = true;
    bool remove_ok = true;
    rp::FolderOutcome finished{rp::FolderEnd::queued, ""};
    rp::FolderOutcome queue_answer{rp::FolderEnd::queued, ""};
    std::vector<std::string> calls;
    std::optional<bool> replaced;
    std::optional<std::string> result; // what the tail was given to write

    rp::CloseRunCalls make()
    {
        rp::CloseRunCalls out;
        out.look = [this] {
            calls.emplace_back("look");
            return folder;
        };
        out.make_folder = [this] {
            calls.emplace_back("make_folder");
            return make_ok;
        };
        out.remove_unfinished = [this] {
            calls.emplace_back("remove_unfinished");
            return remove_ok;
        };
        out.finish = [this](bool replace,
                            const std::function<std::optional<std::string>(const rp::Evidence&)>&
                                build) {
            calls.emplace_back("finish");
            replaced = replace;
            result = build(two_empty_files());
            return result ? finished : rp::FolderOutcome{rp::FolderEnd::incomplete, "invalid"};
        };
        out.queue = [this] {
            calls.emplace_back("queue");
            return queue_answer;
        };
        return out;
    }
};

rp::FolderContents there()
{
    rp::FolderContents folder;
    folder.exists = true;
    return folder;
}

} // namespace

TEST_CASE("a folder that can't be made, or cleared of what a signing left, isn't closed",
          "[service_recovery]")
{
    FakeClose fake;
    SECTION("the folder can't be made")
    {
        fake.make_ok = false;
        const rp::CloseRunOutcome outcome = rp::close_run(requested(), fake.make());
        CHECK(outcome.state == rp::CloseRunState::not_closed);
        CHECK(outcome.word == "not_written");
        CHECK(fake.calls == std::vector<std::string>{"look", "make_folder"});
    }
    SECTION("a signature.json can't be taken away")
    {
        fake.folder = there();
        fake.folder.signature = true;
        fake.remove_ok = false;
        const rp::CloseRunOutcome outcome = rp::close_run(requested(), fake.make());
        CHECK(outcome.state == rp::CloseRunState::not_closed);
        CHECK(outcome.word == "not_written");
        CHECK(fake.calls == std::vector<std::string>{"look", "remove_unfinished"});
    }
}

TEST_CASE("a folder that couldn't be listed whole isn't closed, made, cleared or queued",
          "[service_recovery]")
{
    // A listing that stopped short could leave out a result.json that is
    // there: the close would take its signature.json away.
    FakeClose fake;
    fake.folder = there();
    fake.folder.list_failed = true;
    fake.folder.signature = true;
    const rp::CloseRunOutcome outcome = rp::close_run(requested(), fake.make());
    CHECK(outcome.state == rp::CloseRunState::not_closed);
    CHECK(outcome.word == "not_read");
    CHECK(fake.calls == std::vector<std::string>{"look"});
}

TEST_CASE("a close that the tail ends short keeps the tail's word", "[service_recovery]")
{
    struct Row {
        rp::FolderEnd end;
        std::string word;
        rp::CloseRunState state;
    };
    const Row row = GENERATE(Row{rp::FolderEnd::incomplete, "vault", rp::CloseRunState::not_closed},
                             Row{rp::FolderEnd::incomplete, "not_signed",
                                 rp::CloseRunState::not_closed},
                             Row{rp::FolderEnd::incomplete, "holds_secret",
                                 rp::CloseRunState::not_closed},
                             Row{rp::FolderEnd::incomplete, "changed",
                                 rp::CloseRunState::not_closed},
                             Row{rp::FolderEnd::complete, "not_moved",
                                 rp::CloseRunState::not_queued},
                             Row{rp::FolderEnd::complete, "already_queued",
                                 rp::CloseRunState::not_queued},
                             Row{rp::FolderEnd::queued, "manifest_not_written",
                                 rp::CloseRunState::queued},
                             Row{rp::FolderEnd::queued, "", rp::CloseRunState::queued});
    CAPTURE(row.word);
    FakeClose fake;
    fake.folder = there();
    fake.finished = {row.end, row.word};

    const rp::CloseRunOutcome outcome = rp::close_run(requested(), fake.make());

    CHECK(outcome.state == row.state);
    CHECK(outcome.word == row.word);
    CHECK(fake.calls == std::vector<std::string>{"look", "finish"});
}

TEST_CASE("a record whose result the schema doesn't take is closed as nothing",
          "[service_recovery]")
{
    // Only a record made in code can be one: the reader refuses it.
    RunningRecord record = requested();
    record.connector->name = "other";
    FakeClose fake;
    fake.folder = there();

    const rp::CloseRunOutcome outcome = rp::close_run(record, fake.make());

    CHECK(outcome.state == rp::CloseRunState::not_closed);
    CHECK(outcome.word == "invalid");
    CHECK_FALSE(fake.result);
}

TEST_CASE("a folder whose result.json or signature.json is of an owner the service doesn't "
          "trust is not queued",
          "[service_recovery]")
{
    // 0: result.json, 1: signature.json, 2: timestamp.tst (uploaded as a part too).
    const int by = GENERATE(0, 1, 2);
    CAPTURE(by);
    FakeClose fake;
    fake.folder = there();
    fake.folder.result = true;
    fake.folder.signature = true;
    fake.folder.timestamp = true;
    fake.folder.result_untrusted = by == 0;
    fake.folder.signature_untrusted = by == 1;
    fake.folder.timestamp_untrusted = by == 2;
    // The text files' owners don't matter here: the flush holds them to the
    // hashes the result lists.
    fake.folder.items_csv = true;
    fake.folder.items_csv_untrusted = true;

    CHECK(rp::plan_close(requested(), fake.folder).action == rp::CloseAction::refuse);
    const rp::CloseRunOutcome outcome = rp::close_run(requested(), fake.make());

    CHECK(outcome.state == rp::CloseRunState::not_closed);
    CHECK(outcome.word == "untrusted");
    CHECK_FALSE(outcome.untrusted_text_files);
    // Nothing is queued, signed, taken away or written.
    CHECK(fake.calls == std::vector<std::string>{"look"});
}

TEST_CASE("a text file of an owner the service doesn't trust is replaced, both are, and the "
          "outcome says so",
          "[service_recovery]")
{
    struct Row {
        bool csv;
        bool csv_untrusted;
        bool log;
        bool log_untrusted;
        bool replaced;
    };
    const Row row = GENERATE(Row{true, true, true, false, true},
                             Row{true, false, true, true, true},
                             Row{true, true, false, false, true},
                             Row{true, false, true, false, false},
                             // A flag of a file that isn't there says nothing.
                             Row{false, true, false, true, false});
    CAPTURE(row.csv, row.csv_untrusted, row.log, row.log_untrusted);
    FakeClose fake;
    fake.folder = there();
    fake.folder.items_csv = row.csv;
    fake.folder.items_csv_untrusted = row.csv_untrusted;
    fake.folder.session_log = row.log;
    fake.folder.session_log_untrusted = row.log_untrusted;
    // A signature that didn't get its result is taken away whoever owns it.
    fake.folder.signature_untrusted = true;

    const rp::ClosePlan plan = rp::plan_close(requested(), fake.folder);
    CHECK(plan.action == rp::CloseAction::close);
    CHECK(plan.untrusted_text_files == row.replaced);
    CHECK(plan.replace_text_files == row.replaced);
    CHECK(plan.code == "interrupted");

    const rp::CloseRunOutcome outcome = rp::close_run(requested(), fake.make());

    CHECK(outcome.state == rp::CloseRunState::queued);
    CHECK(outcome.untrusted_text_files == row.replaced);
    CHECK(fake.replaced == row.replaced);
}

TEST_CASE("a close that ends short after replacing untrusted text files still says it did",
          "[service_recovery]")
{
    FakeClose fake;
    fake.folder = there();
    fake.folder.session_log = true;
    fake.folder.session_log_untrusted = true;
    fake.finished = {rp::FolderEnd::incomplete, "vault"};

    const rp::CloseRunOutcome outcome = rp::close_run(requested(), fake.make());

    CHECK(outcome.state == rp::CloseRunState::not_closed);
    CHECK(outcome.word == "vault");
    CHECK(outcome.untrusted_text_files);
}

TEST_CASE("a signature.json flag without a signature.json doesn't keep a complete folder from "
          "the outbox",
          "[service_recovery]")
{
    FakeClose fake;
    fake.folder = there();
    fake.folder.result = true;
    fake.folder.signature_untrusted = true;

    CHECK(rp::plan_close(requested(), fake.folder).action == rp::CloseAction::queue_only);
    CHECK(rp::close_run(requested(), fake.make()).state == rp::CloseRunState::queued);
}

TEST_CASE("a folder with its result.json is only queued: nothing is signed twice",
          "[service_recovery]")
{
    const bool queued = GENERATE(false, true);
    FakeClose fake;
    fake.folder = there();
    fake.folder.result = true;
    fake.folder.signature = true;
    fake.folder.temp_files = true;
    fake.queue_answer = queued ? rp::FolderOutcome{rp::FolderEnd::queued, ""}
                               : rp::FolderOutcome{rp::FolderEnd::complete, "not_moved"};

    // Whatever the record says it is to be closed as: a close cut short
    // after its result.json was written.
    const rp::CloseRunOutcome outcome =
        rp::close_run(rp::with_close(requested(), CloseAs::internal, "changed"), fake.make());

    CHECK(outcome.state ==
          (queued ? rp::CloseRunState::queued : rp::CloseRunState::not_queued));
    CHECK(outcome.word == (queued ? "" : "not_moved"));
    CHECK(fake.calls == std::vector<std::string>{"look", "queue"});
}

TEST_CASE("a close in point 7's order, the tail handed the result written afterwards",
          "[service_recovery]")
{
    FakeClose fake;
    std::vector<std::string> calls{"look", "finish"};
    RunningRecord record = requested();
    bool replace = false;
    std::string code = "interrupted";
    SECTION("a folder that isn't there is made")
    {
        calls = {"look", "make_folder", "finish"};
    }
    SECTION("a job that is no job gets its folder and its result")
    {
        record = rp::new_job_invalid_record("job-0001", std::nullopt, short_profile(), at(kTaken),
                                            "unknown key");
        calls = {"look", "make_folder", "finish"};
        code = "job_invalid";
        replace = true;
    }
    SECTION("an empty folder is closed as it is")
    {
        fake.folder = there();
    }
    SECTION("what a signing left is taken away first")
    {
        fake.folder = there();
        fake.folder.items_csv = true;
        fake.folder.timestamp = true;
        calls = {"look", "remove_unfinished", "finish"};
    }
    SECTION("a temp file alone is taken away too")
    {
        fake.folder = there();
        fake.folder.temp_files = true;
        calls = {"look", "remove_unfinished", "finish"};
    }
    SECTION("text files the run found changed are replaced")
    {
        fake.folder = there();
        fake.folder.items_csv = true;
        fake.folder.session_log = true;
        record = rp::with_close(std::move(record), CloseAs::internal, "changed");
        replace = true;
        code = "internal";
    }

    const rp::CloseRunOutcome outcome = rp::close_run(record, fake.make());

    CHECK(outcome.state == rp::CloseRunState::queued);
    CHECK(outcome.word.empty());
    CHECK(fake.calls == calls);
    CHECK(fake.replaced == replace);
    REQUIRE(fake.result);
    const json document = json::parse(*fake.result);
    CHECK(rp::canonical_json(document) == *fake.result);
    CHECK(rp::validate_result(document).valid);
    CHECK(document["status"]["error_code"] == code);
    CHECK(document["run_id"] == "job-0001");
}

// ------------------------------------------------------------------ the hold

namespace {

struct HoldRow {
    std::string name;
    bool restore_requested;
    std::vector<std::pair<std::string, int>> running; // id, created so many seconds after taken
    int now_s;        // seconds after the last restore request
    int hold_began_s; // the same
    rp::HoldStep step;
    std::vector<std::string> end;
    std::size_t others;
    std::optional<int> others_since;
    bool clean_due;
};

std::vector<HoldRow> hold_rows()
{
    using rp::HoldStep;
    return {
        // No restore request: nothing of the run is restoring.
        {"no request: three recorded running and one other", false,
         {{"a", 1}, {"x", 2}, {"b", 3}, {"c", 4}}, 5, 0, HoldStep::end, {"a", "b", "c"}, 1, 2,
         false},
        {"no request: the other alone is not the run's", false, {{"x", 2}}, 5, 0, HoldStep::over,
         {}, 1, 2, false},
        {"no request: nothing running", false, {}, 5, 0, HoldStep::over, {}, 0, std::nullopt,
         false},
        {"no request: one recorded session no longer listed", false, {{"b", 3}}, 5, 0,
         HoldStep::end, {"b"}, 0, std::nullopt, false},
        // After a request: never end one while another might be a restore.
        {"request: another session running, long past the wait", true, {{"a", 1}, {"x", 70}},
         4000, 0, HoldStep::wait, {}, 1, 70, false},
        {"request: two others, the oldest named", true, {{"y", 90}, {"x", 70}, {"a", 1}}, 4000, 0,
         HoldStep::wait, {}, 2, 70, false},
        {"request: an other alone", true, {{"x", 70}}, 4000, 0, HoldStep::wait, {}, 1, 70, false},
        {"request: none other, one second before the wait is over", true, {{"a", 1}, {"b", 2}},
         119, 0, HoldStep::wait, {}, 0, std::nullopt, false},
        {"request: none other, the wait over", true, {{"a", 1}, {"b", 2}}, 120, 0, HoldStep::end,
         {"a", "b"}, 0, std::nullopt, false},
        {"request: the wait counted from the hold's start when that is later", true, {{"a", 1}},
         419, 300, HoldStep::wait, {}, 0, std::nullopt, false},
        {"request: the wait from the hold's start over", true, {{"a", 1}}, 420, 300,
         HoldStep::end, {"a"}, 0, std::nullopt, false},
        {"request: the hold began before the last request", true, {{"a", 1}}, 119, -50,
         HoldStep::wait, {}, 0, std::nullopt, false},
        {"request: a recorded session no longer listed", true, {{"c", 3}}, 500, 0, HoldStep::end,
         {"c"}, 0, std::nullopt, false},
        {"request: nothing running, the clean is due", true, {}, 5, 0, HoldStep::over, {}, 0,
         std::nullopt, true},
    };
}

} // namespace

TEST_CASE("the hold: what one look at the sessions decides", "[service_recovery]")
{
    const HoldRow row = GENERATE(from_range(hold_rows()));
    CAPTURE(row.name);

    RunningRecord record = requested();
    if (!row.restore_requested) {
        record.restore_requested = false;
        record.restore_requested_at.reset();
    }
    std::vector<rp::connector::OwnSession> running;
    for (const auto& [id, seconds] : row.running) {
        running.push_back({id, at(kTaken) + std::chrono::seconds{seconds}});
    }
    const TimePoint base = at(kRequested);

    const rp::HoldDecision decision =
        rp::decide_hold(record, running, base + std::chrono::seconds{row.now_s},
                        base + std::chrono::seconds{row.hold_began_s});

    CHECK(decision.step == row.step);
    CHECK(decision.end == row.end);
    CHECK(decision.others == row.others);
    CHECK(decision.others_since.has_value() == row.others_since.has_value());
    if (decision.others_since && row.others_since) {
        CHECK(*decision.others_since == at(kTaken) + std::chrono::seconds{*row.others_since});
    }
    CHECK(decision.clean_due == row.clean_due);
}

TEST_CASE("a request's time that doesn't read counts the wait from the hold's start",
          "[service_recovery]")
{
    // Only a record made in code: the reader refuses it.
    RunningRecord record = requested();
    record.restore_requested_at = GENERATE(std::optional<std::string>{},
                                           std::optional<std::string>{"then"});
    const std::vector<rp::connector::OwnSession> running{{"a", at(kTaken)}};
    const TimePoint began = at(kRequested) + 1h;

    CHECK(rp::decide_hold(record, running, began + 119s, began).step == rp::HoldStep::wait);
    CHECK(rp::decide_hold(record, running, began + 120s, began).step == rp::HoldStep::end);
}

TEST_CASE("which record needs the hold when only the record is known", "[service_recovery]")
{
    CHECK_FALSE(rp::needs_hold(taken()));
    CHECK_FALSE(rp::needs_hold(started()));
    CHECK(rp::needs_hold(rp::with_session(started(), "a")));
    CHECK(rp::needs_hold(rp::with_restore_request(started(), at(kRequested))));
    CHECK(rp::needs_hold(requested()));
}

// ------------------------------------------------------------ when it goes

namespace {

rp::PipelineReport report_of(bool run_line, rp::RunFolderState folder, bool may_still_run)
{
    rp::PipelineReport report;
    report.run_id = "job-0001";
    report.run_line = run_line;
    report.folder = folder;
    report.restore_may_still_run = may_still_run;
    return report;
}

} // namespace

TEST_CASE("the record stays while the run's folder is in nobody's queue", "[service_recovery]")
{
    using rp::OutboxHolds;
    using rp::RunFolderState;
    // Found at start: no report.
    CHECK_FALSE(rp::record_may_go(taken(), OutboxHolds::none, nullptr, true));
    // The run returned and left its folder under the runs root.
    for (const RunFolderState folder : {RunFolderState::incomplete, RunFolderState::complete}) {
        const rp::PipelineReport report = report_of(true, folder, false);
        CHECK_FALSE(rp::record_may_go(started(), OutboxHolds::none, &report, true));
    }
    // A run line and no folder said: not "ended before its run line".
    const rp::PipelineReport lined = report_of(true, RunFolderState::none, false);
    CHECK_FALSE(rp::record_may_go(started(), OutboxHolds::none, &lined, true));
    // No run line, and a folder all the same.
    const rp::PipelineReport foldered = report_of(false, RunFolderState::incomplete, false);
    CHECK_FALSE(rp::record_may_go(taken(), OutboxHolds::none, &foldered, true));
}

TEST_CASE("the record stays while a restore of the run may still be running",
          "[service_recovery]")
{
    using rp::OutboxHolds;
    using rp::RunFolderState;
    // Found at start with a restore requested, or sessions nobody closed.
    CHECK_FALSE(rp::record_may_go(requested(), OutboxHolds::queued, nullptr, false));
    CHECK_FALSE(rp::record_may_go(requested(), OutboxHolds::sent, nullptr, false));
    CHECK_FALSE(
        rp::record_may_go(rp::with_session(started(), "a"), OutboxHolds::queued, nullptr, false));
    // Ended in this process, in its restore phase, without the promise.
    const rp::PipelineReport still = report_of(true, RunFolderState::queued, true);
    CHECK_FALSE(rp::record_may_go(requested(), OutboxHolds::queued, &still, false));
}

TEST_CASE("the record goes once the run is in the outbox and nothing of it can be running",
          "[service_recovery]")
{
    using rp::OutboxHolds;
    using rp::RunFolderState;
    // A run that ended before its run line has no folder and sent nothing.
    const rp::PipelineReport not_started = report_of(false, RunFolderState::none, false);
    CHECK(rp::record_may_go(taken(), OutboxHolds::none, &not_started, false));
    // A run that ended by itself closed its sessions and cleaned after.
    const rp::PipelineReport ended = report_of(true, RunFolderState::queued, false);
    CHECK(rp::record_may_go(requested(), OutboxHolds::queued, &ended, false));
    CHECK(rp::record_may_go(requested(), OutboxHolds::sent, &ended, false));
    // The report's word without a request on record: no restore went out.
    const rp::PipelineReport still = report_of(true, RunFolderState::queued, true);
    CHECK(rp::record_may_go(rp::with_session(started(), "a"), OutboxHolds::queued, &still,
                            false));
    // The hold done.
    CHECK(rp::record_may_go(requested(), OutboxHolds::queued, &still, true));
    CHECK(rp::record_may_go(requested(), OutboxHolds::sent, nullptr, true));
    // Found at start with nothing to hold for: a job that is no job, a run
    // killed before it opened a session.
    CHECK(rp::record_may_go(taken(), OutboxHolds::queued, nullptr, false));
    CHECK(rp::record_may_go(rp::new_job_invalid_record("job-0002", std::nullopt, short_profile(),
                                                       at(kTaken), "sample_od"),
                            OutboxHolds::sent, nullptr, false));
}
