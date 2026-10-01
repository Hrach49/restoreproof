#pragma once

// The Office file content rule "office-v1" (lab/README.md, "Office file
// content: rule office-v1"; lab/seeder/office.py). SharePoint rewrites a docx
// or xlsx it stores (metadata, relationships, content types, [trash]/ parts)
// but leaves the document content byte for byte, so the checker (W3.2)
// compares the content parts only. The vectors both implementations must
// agree on are shared/testdata/office-content-v1/.

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace rp {

inline constexpr std::string_view kOfficeV1 = "office-v1";

// The file can't be hashed by office-v1: a type without a rule, or a package
// that isn't valid (not a ZIP, no content part, a part twice, a bad CRC, an
// unsupported or encrypted entry, a limit hit). For a restored file that is a
// content mismatch, not an infrastructure error: the file is broken, not the test.
class OfficeContentError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// What one package may hold, so a zip bomb is a refusal. The defaults match
// the download cap (64 MiB, rp/graph_download.hpp); tests set small ones.
struct OfficeLimits {
    std::uint64_t max_part_bytes = 64ULL * 1024 * 1024;   // one content part, uncompressed
    std::uint64_t max_total_bytes = 64ULL * 1024 * 1024;  // all content parts together
    std::uint64_t max_entries = 10000;                    // central directory entries
};

// The lines office-v1 hashes, one per content part sorted by its name's UTF-8
// bytes: lower-case hex SHA-256 of the uncompressed part, two spaces, the
// name, LF. Content parts are those whose name starts with "word/" (docx) or
// "xl/" (xlsx), case-sensitive, has no "_rels/" anywhere and doesn't end in
// "/". `file_type` is the manifest's, exactly "docx" or "xlsx". Useful to see
// which part differs. Throws OfficeContentError.
std::string office_v1_listing(std::string_view bytes, std::string_view file_type,
                              const OfficeLimits& limits = {});

// sha256_hex(office_v1_listing(bytes, file_type)): what the manifest's
// content_sha256 holds for a docx or xlsx. Throws OfficeContentError.
std::string office_v1_sha256(std::string_view bytes, std::string_view file_type,
                             const OfficeLimits& limits = {});

} // namespace rp
