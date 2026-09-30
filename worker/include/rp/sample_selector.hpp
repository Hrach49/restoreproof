#pragma once

// The sampler (W2.6; docs/decisions.md 2026-09-30, W2.6): which items a run
// restores. Per type, half the sample size (rounded up) are canaries taken in
// turn from the manifest by a cursor, and half (rounded down) are drawn from
// the real data IConnector::list_candidates offers, with the portable draws of
// rp/sample_rng.hpp seeded from the run ID. select is pure, so a run's
// selection can be repeated from what its result records.

#include <rp/canary_manifest.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/sample_rng.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rp::sampling {

// Items to restore per type, 0 to 100 each.
struct SamplePlan {
    int mail = 0;
    int sharepoint = 0;
    int onedrive = 0;

    // sample_mail, sample_sp and sample_od.
    static SamplePlan from_config(const Config& config);
};

// Where each type's canary rotation starts: an index into the manifest's
// canaries of that type, below their number (0 when there are none). The
// Worker keeps no state: the result carries the next run's (W2.6 point 3).
struct CanaryCursor {
    std::uint32_t mail = 0;
    std::uint32_t sharepoint = 0;
    std::uint32_t onedrive = 0;
};

// What one type's selection was, for the result bundle.
struct KindRecord {
    int requested = 0;
    std::uint32_t cursor = 0;
    std::uint32_t cursor_next = 0;
    int canary_wanted = 0;
    std::vector<std::string> canary_ids; // in rotation order
    int random_wanted = 0;
    int random_taken = 0;                // below random_wanted: a shortfall, not filled
    std::size_t pool_size = 0;           // candidates after deduplication
    std::string pool_sha256;             // of the sorted keys (see select)
    std::vector<std::vector<std::string>> random_keys; // those taken, in draw order
    connector::BrowseRecord browse;
};

struct SampleRecord {
    std::string algorithm{kAlgorithm};
    std::string run_id;
    std::uint32_t seed = 0;
    std::string manifest_sha256;
    KindRecord mail;
    KindRecord sharepoint;
    KindRecord onedrive;
};

// The result's "sample" object: {"algorithm", "run_id", "seed" (8 hex
// digits), "manifest_sha256", and per type "mail"/"sharepoint"/"onedrive":
// {"requested", "canary": {"cursor", "cursor_next", "wanted", "ids"},
// "random": {"wanted", "taken", "pool_size", "pool_sha256", "keys",
// "containers_eligible", "containers_listed", "containers_unresolved",
// "folders_listed", "short_of_containers"}}}.
nlohmann::json to_json(const SampleRecord& record);

struct Selection {
    // Per type, the canaries first, then the random items (size -1).
    std::vector<connector::MailSelector> mail;
    std::vector<connector::SharePointSelector> sharepoint;
    std::vector<connector::OneDriveSelector> onedrive;
    SampleRecord record;
};

class SampleSelector {
public:
    // Pure: no I/O, no clock. The seed is derived from run_id here, so no
    // caller can pass one the run ID didn't give. Per type, with N the plan's
    // size and M the manifest's canaries:
    //  - canaries: c = min(ceil(N/2), M) from the cursor on (mod M), the next
    //    cursor (cursor + c) mod M;
    //  - random: floor(N/2) drawn from the pool, sorted by key and
    //    deduplicated first (mail [mailbox lower case, folder, subject,
    //    received_at]; SharePoint [site_id lower case, list_id lower case,
    //    folder_path, name]; OneDrive [user lower case, folder_path, name]),
    //    by a Shuffle on the type's items stream. A pick whose subject or name
    //    is already taken, the case of any letter aside (src/name_key.hpp,
    //    Unicode), is skipped, its draw used up. Too few candidates is a
    //    shortfall, recorded and not filled.
    // Throws std::invalid_argument for a bad run ID, a size outside 0..100 or
    // a cursor out of range; ManifestError for a canary in a restore target;
    // std::logic_error ("sampler: the connector offered ...") when the pool
    // holds a candidate list_candidates must never offer (a restore target, a
    // canary or a canary location), and then nothing is sampled.
    static Selection select(const SamplePlan& plan, const CanaryManifest& manifest,
                            const CanaryCursor& cursor, const connector::RestoreTargets& targets,
                            const connector::CandidatePool& pool, std::string_view run_id);
};

// A run's sample: connector.list_candidates for the types whose random half is
// above 0 (not called when none is), then SampleSelector::select. The query
// excludes the manifest's canary libraries, subjects and names. Checks first,
// before the connector is called: the run ID, the plan and cursor as select
// does, manifest.tenant_id against graph_tenant_id (ASCII case-insensitive;
// else ManifestError), and no canary in a restore target (ManifestError, as
// select). The connector's errors pass out.
Selection choose_sample(connector::IConnector& connector, const std::string& client_ref,
                        const connector::RestorePoint& point,
                        const connector::RestoreTargets& targets,
                        const std::string& graph_tenant_id, const SamplePlan& plan,
                        const CanaryManifest& manifest, const CanaryCursor& cursor,
                        std::string_view run_id, const connector::CandidateLimits& limits = {});

} // namespace rp::sampling
