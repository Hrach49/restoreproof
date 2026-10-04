#pragma once

// lab/seed-manifest.json (seed-manifest.v1, shared/schemas/seed-manifest.v1.json):
// the canary items, as far as the sampler (W2.6) and the expected set (W3.1)
// use them: where each canary is, and the fields and content hash its
// restored copy is compared with. The rules are the loader's own, not the
// schema's: a pilot's manifest may hold another number of canaries, and a
// field no rule names is ignored (docs/decisions.md 2026-09-30, W2.6, and
// 2026-10-01, W3.1).

#include <rp/connector.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rp::sampling {

// How a file's content is compared (lab/README.md): all bytes, or office-v1's
// content parts, since SharePoint rewrites docx and xlsx.
enum class ContentRule { bytes, office_v1 };

struct CanaryMail {
    std::size_t entry = 0; // its index in the manifest's /entries
    std::string id;
    std::string mailbox;     // location.mailbox
    std::string folder;      // location.folder
    std::string subject;
    std::string received_at; // "YYYY-MM-DDTHH:MM:SSZ"
    std::string sender;      // an address, as Graph's from.emailAddress.address
    std::string sent_at;     // "YYYY-MM-DDTHH:MM:SSZ"
    std::string internet_message_id;
    std::string body_sha256;        // lower-case hex, of the body by body_normalization
    std::string body_normalization; // "text-v1", the only one known
};

struct CanaryFile {
    std::size_t entry = 0; // its index in the manifest's /entries
    std::string id;
    std::string name;
    std::string file_type; // pdf, docx, xlsx, txt or png
    ContentRule content_rule = ContentRule::bytes;
    std::int64_t stored_size = 0;
    // Lower-case hex, by content_rule: what a restored copy is compared with.
    std::string content_sha256;
    std::string folder_path; // location.folder_path, "/" first
    // sharepoint_file only: location.site_id (Graph), drive_id (Graph), list_id.
    std::string site_id;
    std::string drive_id;
    std::string list_id;
    // onedrive_file only: location.user, the OneDrive's owner.
    std::string user;
};

struct CanaryManifest {
    std::string tenant_id;
    // "YYYY-MM-DDTHH:MM:SSZ": when every canary was in place (the seeder
    // writes it after the last one). A restore point taken later holds them
    // all, so one missing from it is the backup's failure (Q3.1).
    std::string seeded_at;
    // Lower-case hex SHA-256 of the manifest file's bytes, for the result.
    std::string sha256;
    // Each kind in manifest order: the rotation's order.
    std::vector<CanaryMail> mail;
    std::vector<CanaryFile> sharepoint;
    std::vector<CanaryFile> onedrive;
};

// A manifest that can't be read or breaks a rule. what() is
// "canary manifest: <JSON pointer>: <rule>" (or, for the whole file,
// "canary manifest: <rule>"); it never quotes a value from the file.
class ManifestError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Parses seed-manifest.v1 text. Refused (ManifestError): text that isn't a
// JSON object (a number too large for a double included); a schema other than "seed-manifest.v1"; a tenant_id that isn't
// a GUID; entries that aren't an array of objects of kind mail,
// sharepoint_file or onedrive_file; an id missing, empty or repeated; a mail
// without subject, mailbox or folder, from a restoretest mailbox or one whose
// address holds whitespace or a control character, with a received_at or
// sent_at that isn't "YYYY-MM-DDTHH:MM:SSZ" or not a real date and time
// (month 13, 31 September, hour 24, second 60), a sender that isn't one "@"
// with no whitespace or control character, an internet_message_id missing,
// empty or with a control character, a body_normalization other than
// "text-v1", or a body_sha256 that isn't 64 lower-case hex digits; a file
// without name, with another file_type or content_rule, a content_rule other
// than office-v1 for a docx or xlsx and bytes for a pdf, txt or png, a name
// that is one SharePoint rewrites (src/office_files.hpp) for a pdf, txt or png or
// isn't one for a docx or xlsx, a stored_size below
// 0, a content_sha256 that isn't 64 lower-case hex digits, or a folder_path not
// starting with "/" or with a ".." segment, a backslash or a colon; a SharePoint file whose site_id,
// drive_id or list_id isn't a Graph site ID, a Graph drive ID or a GUID; a
// OneDrive file without user; two subjects equal but for ASCII case; two
// names of one kind equal but for the case of any letter (src/name_key.hpp:
// restore_sample would refuse them in one run).
CanaryManifest parse_canary_manifest(std::string_view json_text);

// The file's bytes, then parse_canary_manifest. ManifestError if it can't be read.
CanaryManifest load_canary_manifest(const std::filesystem::path& path);

// A canary as restore_sample takes it. A file's size is its stored_size for a
// `bytes` file and -1 (unchecked) for an office-v1 one: SharePoint rewrites
// docx and xlsx, so their stored size is evidence only (W2.6 point 9).
connector::MailSelector to_selector(const CanaryMail& canary);
connector::SharePointSelector to_sharepoint_selector(const CanaryFile& canary);
connector::OneDriveSelector to_onedrive_selector(const CanaryFile& canary);

} // namespace rp::sampling
