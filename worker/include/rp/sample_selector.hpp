#pragma once

// The sampler (W2.6; docs/decisions.md 2026-09-30, W2.6): which items a run
// restores. With canaries (W6.2: an opt-in, docs/decisions.md 2026-10-14,
// W6.3 and W6.2, points 9 and 10), per type half the sample size (rounded
// up) are canaries taken in turn from the manifest by a cursor, and half
// (rounded down) are drawn from the real data IConnector::list_candidates
// offers; without canaries the whole sample is drawn from the real data.
// The draws are the portable ones of rp/sample_rng.hpp seeded from the run
// ID. select is pure, so a run's selection can be repeated from what its
// result records.

#include <rp/canary_manifest.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/sample_rng.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
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
    // W6.2: whether the run had canaries (a manifest). Without, the whole
    // sample is random items, manifest_sha256 is empty and each type's
    // rotation (cursor, cursor_next, canary_wanted, canary_ids) is 0 and empty
    // and not written.
    bool canaries = true;
    std::string manifest_sha256;
    KindRecord mail;
    KindRecord sharepoint;
    KindRecord onedrive;
};

// The result's "sample" object: {"algorithm", "run_id", "seed" (8 hex
// digits), "manifest_sha256", and per type "mail"/"sharepoint"/"onedrive":
// {"requested", "canary": {"cursor", "cursor_next", "wanted", "ids"},
// "random": {"wanted", "taken", "pool_size", "pool_sha256", "keys",
// "containers_eligible", "containers_drawn", "containers_unresolved",
// "folders_listed", "short_of_containers"}}}. "containers_drawn" is how many
// containers the draw looked into (BrowseRecord::containers_listed's length):
// their names are of containers the run didn't test and stay out of the result.
// W6.2: without canaries "manifest_sha256" and each type's "canary" object
// are left out (never null): facts of a rotation the run didn't have.
nlohmann::json to_json(const SampleRecord& record);

struct Selection {
    // Per type, the canaries first, then the random items (size -1).
    std::vector<connector::MailSelector> mail;
    std::vector<connector::SharePointSelector> sharepoint;
    std::vector<connector::OneDriveSelector> onedrive;
    // Per type, the random candidates taken, in the order their selectors
    // follow the canaries, with what the backup listed beside the key (W3.1:
    // a mail's sender name and sent time, a file's size_bytes); each
    // selector's size -1, as in the selectors above. Per type, selectors ==
    // record.canary_ids + <kind>_random in number.
    std::vector<connector::MailCandidate> mail_random;
    std::vector<connector::SharePointCandidate> sharepoint_random;
    std::vector<connector::OneDriveCandidate> onedrive_random;
    SampleRecord record;
};

class SampleSelector {
public:
    // Pure: no I/O, no clock. The seed is derived from run_id here, so no
    // caller can pass one the run ID didn't give. `manifest` null (W6.2): the
    // run has no canaries, every cursor must be 0, and per type the whole
    // size N is random. With one, per type, with N the plan's size and M the
    // manifest's canaries:
    //  - canaries: c = min(ceil(N/2), M) from the cursor on (mod M), the next
    //    cursor (cursor + c) mod M;
    //  - random: floor(N/2) drawn from the pool, sorted by key and
    //    deduplicated first (mail [mailbox lower case, folder, subject,
    //    received_at]; SharePoint [site_id lower case, list_id lower case,
    //    folder_path, name]; OneDrive [user lower case, folder_path, name]),
    //    by a Shuffle on the type's items stream (candidates of one key and
    //    equal fields sorted by their facts too, so the one kept doesn't
    //    depend on the pool's order). A pick whose subject or name
    //    is already taken, the case of any letter aside (src/name_key.hpp,
    //    Unicode), is skipped, its draw used up. Too few candidates is a
    //    shortfall, recorded and not filled.
    // Throws std::invalid_argument for a bad run ID, a size outside 0..100 or
    // a cursor out of range; ManifestError for a canary in a restore target;
    // std::logic_error ("sampler: the connector offered ...") when the pool
    // holds a candidate list_candidates must never offer (a restore target, a
    // canary or a canary location), and then nothing is sampled.
    static Selection select(const SamplePlan& plan, const CanaryManifest* manifest,
                            const CanaryCursor& cursor, const connector::RestoreTargets& targets,
                            const connector::CandidatePool& pool, std::string_view run_id);
};

// A random candidate's key, as select sorts, deduplicates and records it
// (KindRecord::random_keys): mail [mailbox lower case, folder, subject,
// received_at]; SharePoint [site_id lower case, list_id lower case,
// folder_path, name]; OneDrive [user lower case, folder_path, name].
std::vector<std::string> random_key(const connector::MailSelector& mail);
std::vector<std::string> random_key(const connector::SharePointSelector& file);
std::vector<std::string> random_key(const connector::OneDriveSelector& file);

// Why `cursor` is out of `manifest`'s range, for the first type that is (mail,
// sharepoint, onedrive): "the <kind> cursor must be below <n>, the manifest's
// <kind> canaries", or "the <kind> cursor must be 0: the manifest has no <kind>
// canaries"; nullopt when every cursor is in range. A null manifest (W6.2) has
// no canaries of any type, so every cursor must be 0. The one cursor rule:
// select throws std::invalid_argument("sampler: " + it), and `rpworker
// restore` says it as a usage error before any Veeam call.
std::optional<std::string> cursor_problem(const CanaryManifest* manifest,
                                          const CanaryCursor& cursor);

// The manifest against the client, pure: manifest.tenant_id is
// graph_tenant_id (ASCII case-insensitive; else ManifestError "canary
// manifest: /tenant_id: isn't the client's tenant (graph_tenant_id)"), and no
// canary is in a restore target (ManifestError "canary manifest:
// /entries/<n>/location/<field>: ..."). choose_sample runs it before the
// connector is called; `rpworker restore` before the connector is made.
void check_manifest(const CanaryManifest& manifest, const connector::RestoreTargets& targets,
                    const std::string& graph_tenant_id);

// Its two halves (W4.11 point 1): the tenant alone, which the pipeline's
// client check runs after the run line so that a job of another tenant is
// reported; and the canaries against the targets alone, which it runs before.
void check_manifest_tenant(const CanaryManifest& manifest, const std::string& graph_tenant_id);
void check_manifest_targets(const CanaryManifest& manifest,
                            const connector::RestoreTargets& targets);

// A run's sample: connector.list_candidates for the types whose random part
// is above 0 (not called when none is), then SampleSelector::select. With a
// manifest the query excludes its canary libraries, subjects, names and
// OneDrive folders, and the checks come first, before the connector is
// called: the run ID, the plan and cursor as select does, then
// check_manifest. Without one (W6.2, null) the query excludes nothing of a
// manifest's (the lister's own rules, the restore targets and the rp-canary-
// prefix, stay) and the whole plan is random. The connector's errors pass
// out.
Selection choose_sample(connector::IConnector& connector, const std::string& client_ref,
                        const connector::RestorePoint& point,
                        const connector::RestoreTargets& targets,
                        const std::string& graph_tenant_id, const SamplePlan& plan,
                        const CanaryManifest* manifest, const CanaryCursor& cursor,
                        std::string_view run_id, const connector::CandidateLimits& limits = {});

} // namespace rp::sampling
