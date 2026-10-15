#pragma once

// What the Worker reads of the Cloud's answers and how it names itself to it
// (W5.1, docs/decisions.md 2026-10-15, "W5.1 (#66)", points 2 and 5): the
// contract header's rule, the bearer header, the token's shape, the
// registration's request and its answer. Nothing here sends anything; the
// routes' callers (rp/cloud_command.hpp, rp/uploader.hpp, src/heartbeat.hpp,
// src/jobs_fetch.hpp) do, and decide what each answer means.
//
// Strict (100% line), by its name.

#include <rp/http_client.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace rp {

inline constexpr std::string_view kRegisterPath = "/v1/workers/register";
inline constexpr std::string_view kJobsPath = "/v1/jobs";

// The contract header (C5.11): every answer the Cloud's app sends carries it,
// with the contract's number. Caddy hands it on as "X-Restoreproof-Api": the
// name is compared in any case, the value exactly.
inline constexpr std::string_view kCloudApiHeader = "X-RestoreProof-API";
inline constexpr std::string_view kCloudApiValue = "1";

// A token as the Cloud makes one: 32 random bytes in base64url, no padding.
inline constexpr std::size_t kCloudTokenLength = 43;

// Whom a 2xx is from (point 5). Read on a 2xx alone: a server's own 400 or
// 503 and a proxy's 502 never reach the app and carry no header.
enum class CloudAnswerKind {
    cloud,         // X-RestoreProof-API: 1
    not_cloud,     // no such header
    other_contract // the header, with another value
};

CloudAnswerKind cloud_answer_kind(const HttpResponse& response) noexcept;

// What a warning may say of another contract's value: the value when it is 1
// to 9 ASCII digits ("2"), else "another value". Never a value's other bytes.
std::string other_contract_text(const HttpResponse& response);

// "Bearer <token>", the Authorization header's value.
std::string bearer(std::string_view token);

// 43 base64url characters (A-Z a-z 0-9 - _), nothing else.
bool is_cloud_token(std::string_view token) noexcept;

// What registration sends as worker_name: 1 to 128 code points of UTF-8 with
// no control character (C0, DEL, C1), the Cloud's own rule.
bool is_worker_name(std::string_view name) noexcept;

// The registration's body (POST /v1/workers/register) as canonical-json-v1:
// {"install_token","public_key_pem","version","worker_name"}. Throws
// rp::CanonicalJsonError for a text that isn't UTF-8.
std::string registration_body(std::string_view install_token, std::string_view public_key_pem,
                              std::string_view worker_name, std::string_view version);

// The 201's body: a closed object of exactly these three.
struct Registration {
    std::string worker_id; // a uuid, as the Cloud wrote it
    std::string api_token; // is_cloud_token
    std::string key_id;    // 64 lower-case hex digits
};

// The 201's body read with strict JSON (a key twice is refused), or nullopt
// for anything else: not an object of exactly the three keys, a value of
// another kind or shape. Never throws but for no memory.
std::optional<Registration> parse_registration(std::string_view body);

// state\worker.json (point 3): the Worker's registration, no secret, as
// canonical-json-v1: {"cloud_url","format","key_id","registered_at",
// "worker_id"}, the time as UTC to the second ("YYYY-MM-DDTHH:MM:SSZ").
inline constexpr std::string_view kWorkerFileName = "worker.json";
inline constexpr std::string_view kWorkerFormat = "restoreproof.worker.v1";

struct WorkerRecord {
    std::string worker_id;
    std::string key_id;
    std::string cloud_url;
    std::string registered_at;
};

std::string worker_record_text(const WorkerRecord& record);

// The record `text` holds, or nullopt for anything that isn't one written by
// worker_record_text (its canonical form, the five keys, the format, a uuid,
// a key id of 64 lower-case hex digits, a time of that shape). Never throws
// but for no memory.
std::optional<WorkerRecord> parse_worker_record(std::string_view text);

} // namespace rp
