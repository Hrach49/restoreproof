#pragma once

// The outbox's tests (rp/outbox.hpp, W4.6): a temp folder with a runs root
// and an outbox root, run folders made as a signed run leaves them (a result
// that lists its attachments, a signature.json naming the result's hash, a
// token of the test-only TSA over that hash), a clock, and an uploader that
// answers what the test set. No network.

#include "test_support.hpp"
#include "tsa_lab.hpp"

#include "../src/utf16.hpp"

#include <rp/outbox.hpp>
#include <rp/rfc3161.hpp>
#include <rp/sha256.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp::test::outbox_lab {

using nlohmann::json;
using std::filesystem::path;

// 2026-10-07T12:00:00Z, and `seconds` after it.
inline std::chrono::system_clock::time_point at(long long seconds = 0)
{
    using namespace std::chrono;
    return sys_days{year{2026} / October / 7} + hours{12} + std::chrono::seconds{seconds};
}

inline std::string text_at(long long seconds = 0)
{
    return rp::outbox_time_text(at(seconds));
}

inline std::string utf8_of(const path& p)
{
    const std::u8string text = p.u8string();
    return {text.begin(), text.end()};
}

inline std::optional<std::string> slurp(const path& file)
{
    std::ifstream stream(file, std::ios::binary);
    if (!stream) {
        return std::nullopt;
    }
    return std::string{std::istreambuf_iterator<char>(stream), {}};
}

inline void spit(const path& file, std::string_view bytes)
{
    std::ofstream stream(file, std::ios::binary | std::ios::trunc);
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    stream.close();
    REQUIRE(stream);
}

// Every file of `folder` but manifest.json, by name.
inline std::map<std::string, std::string> files_of(const path& folder)
{
    std::map<std::string, std::string> files;
    for (const auto& entry : std::filesystem::directory_iterator(folder)) {
        // A name that isn't valid UTF-16 (a test's own) is no file of a run.
        const std::optional<std::string> name = rp::utf16_to_utf8(entry.path().filename().native());
        if (name && *name != "manifest.json") {
            files[*name] = slurp(entry.path()).value_or("?");
        }
    }
    return files;
}

inline const rp::test::TestTsa& tsa()
{
    static const rp::test::TestTsa one;
    return one;
}

// A token of the test-only TSA over SHA-256 of `bytes`.
inline std::string token_over(std::string_view bytes)
{
    const std::array<unsigned char, 32> digest = rp::sha256_bytes(bytes);
    const std::optional<rp::TimestampResponse> response = rp::openssl_rfc3161().parse_response(
        tsa().respond(rp::openssl_rfc3161().request(digest, 7)));
    REQUIRE(response);
    REQUIRE_FALSE(response->token.empty());
    return response->token;
}

struct FakeUploader final : rp::IUploader {
    // Answered in turn, the last one repeating; none = accepted.
    std::vector<rp::UploadAnswer> answers;
    // Called first in each upload; what it throws, the upload throws.
    std::function<void()> at_upload;
    std::vector<std::string> runs;
    std::vector<std::vector<rp::UploadPart>> parts;

    rp::UploadAnswer upload(const std::string& run_id,
                            const std::vector<rp::UploadPart>& sent) override
    {
        runs.push_back(run_id);
        parts.push_back(sent);
        if (at_upload) {
            at_upload();
        }
        if (answers.empty()) {
            return {true, {}};
        }
        return answers[std::min(runs.size() - 1, answers.size() - 1)];
    }
};

inline rp::UploadAnswer failed(std::string code)
{
    return {false, std::move(code)};
}

struct Box {
    rp::test::TempDir dir;
    path runs = dir.path() / "runs";
    path root = dir.path() / "rp";
    rp::OutboxFiles files;

    rp::Outbox outbox() const { return rp::Outbox({root, files, nullptr}); }
    path queued(const std::string& id) const { return root / "outbox" / id; }
    path sent(const std::string& id) const { return root / "sent" / id; }
    // W5.1: a run the Cloud refused for good.
    path refused(const std::string& id) const { return root / "failed" / id; }

    // <runs>\<id> as a signed run leaves it: items.csv and veeam-session.log,
    // a result.json that lists them, a signature.json naming its hash and,
    // with `stamped`, a token over it.
    path make_run(const std::string& id, bool stamped = true) const
    {
        const path folder = runs / id;
        std::filesystem::create_directories(folder);
        const std::string csv = "index,type\n0,\"mail\"\n";
        const std::string log = "session " + id + "\n";
        spit(folder / "items.csv", csv);
        spit(folder / "veeam-session.log", log);
        const json result{
            {"attachments",
             json::array({{{"name", "items.csv"},
                           {"sha256", rp::sha256_hex(csv)},
                           {"size_bytes", csv.size()}},
                          {{"name", "veeam-session.log"},
                           {"sha256", rp::sha256_hex(log)},
                           {"size_bytes", log.size()}}})},
            {"run_id", id}};
        write_result(folder, result.dump(), stamped);
        return folder;
    }

    // result.json as `text`, with a signature.json that names its hash and,
    // with `stamped`, a token over it.
    static void write_result(const path& folder, const std::string& text, bool stamped)
    {
        spit(folder / "result.json", text);
        spit(folder / "signature.json",
             json{{"bundle_sha256", rp::sha256_hex(text)}, {"key_id", "k"}}.dump());
        if (stamped) {
            spit(folder / "timestamp.tst", token_over(text));
        }
    }

    // make_run, queued at `seconds`.
    path queue_run(const std::string& id, long long seconds = 0, bool stamped = true) const
    {
        const rp::QueueOutcome outcome =
            outbox().queue(make_run(id, stamped), id, at(seconds), stamped,
                           stamped ? "" : "tsa_unreachable");
        REQUIRE(outcome.result == rp::QueueResult::queued);
        return outcome.folder;
    }

    // A run under sent\ with a manifest that says it was sent at `seconds`.
    path sent_run(const std::string& id, long long seconds) const
    {
        const path folder = sent(id);
        std::filesystem::create_directories(folder);
        spit(folder / "result.json", "{}");
        rp::OutboxManifest manifest;
        manifest.run_id = id;
        manifest.queued_at = text_at(seconds - 5);
        manifest.attempts = 1;
        manifest.last_attempt_at = text_at(seconds);
        manifest.sent_at = text_at(seconds);
        manifest.timestamped = true;
        spit(folder / "manifest.json", rp::manifest_text(manifest));
        return folder;
    }

    rp::OutboxManifest manifest_of(const path& folder) const
    {
        const std::optional<std::string> text = slurp(folder / "manifest.json");
        REQUIRE(text);
        const std::optional<rp::OutboxManifest> manifest =
            rp::parse_manifest(*text, utf8_of(folder.filename()));
        REQUIRE(manifest);
        return *manifest;
    }
};

} // namespace rp::test::outbox_lab
