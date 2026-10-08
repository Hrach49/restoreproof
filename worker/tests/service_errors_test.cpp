// The words a heartbeat's last_error may be (rp/service_errors.hpp; W4.8,
// docs/decisions.md 2026-10-08 point 11).

#include <rp/outbox.hpp>
#include <rp/run_status.hpp>
#include <rp/service_errors.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <string_view>
#include <vector>

TEST_CASE("service errors: what is no word of the loop's is refused", "[service_errors]")
{
    const std::string word = GENERATE(
        "", "pass", "internal", "graph_transient", "interrupted", "JOBS_UNREADABLE",
        "jobs_unreadable ", "upload_http_", "upload_http_50", "upload_http_5000", "upload_http_5x3",
        "http_500", "unreachable", "tsa_unreachable", "C:\\ProgramData\\RestoreProof",
        "veeam_look_failed: boom");
    CAPTURE(word);

    CHECK_FALSE(rp::is_service_error(word));
}

TEST_CASE("service errors: the fixed list, in the entry's order", "[service_errors]")
{
    const std::vector<std::string_view> expected{
        "jobs_unreadable",    "job_invalid",        "job_not_started",
        "record_not_written", "record_not_removed", "record_unreadable",
        "run_not_closed",     "run_not_queued",     "folder_changed",
        "not_read",           "veeam_look_failed",  "veeam_sessions_working",
        "recovery_clean_incomplete", "upload_unreachable", "upload_timeout",
        "upload_internal"};
    const auto codes = rp::service_error_codes();

    CHECK(std::vector<std::string_view>(codes.begin(), codes.end()) == expected);
    CHECK(std::set<std::string_view>(codes.begin(), codes.end()).size() == codes.size());
    for (const std::string_view code : codes) {
        CAPTURE(std::string{code});
        CHECK(rp::is_service_error(code));
    }
    // The outbox's own words for the two it shares.
    CHECK(rp::service_error::kFolderChanged == rp::upload_code::kFolderChanged);
    CHECK(rp::service_error::kNotRead == rp::kFlushNotRead);
}

TEST_CASE("service errors: an upload's status is one by its pattern", "[service_errors]")
{
    const std::string word = GENERATE("upload_http_500", "upload_http_401", "upload_http_100",
                                      "upload_http_999");
    CAPTURE(word);

    CHECK(rp::is_service_error(word));
    const auto codes = rp::service_error_codes();
    CHECK(std::ranges::find(codes, std::string_view{word}) == codes.end());
}

TEST_CASE("service errors: none but job_invalid shares its word with a run's error code",
          "[service_errors]")
{
    // A heartbeat never carries a run's own code: the result does. job_invalid
    // is the loop's word for a job it reported or couldn't.
    const auto run_codes = rp::verification::error_codes();
    for (const std::string_view code : rp::service_error_codes()) {
        CAPTURE(std::string{code});
        const bool shared = std::ranges::find(run_codes, code) != run_codes.end();
        CHECK(shared == (code == "job_invalid"));
    }
}
