#pragma once

// lab/seed-manifest.json (seed-manifest.v1, shared/schemas/seed-manifest.v1.json):
// the canary items, as far as the sampler (W2.6) uses them. W3.1 and W3.2 add
// the fields they compare with. The rules are the loader's own, not the
// schema's: a pilot's manifest may hold another number of canaries, and a
// field no rule names is ignored (docs/decisions.md 2026-09-30, W2.6).

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
};

struct CanaryFile {
    std::size_t entry = 0; // its index in the manifest's /entries
    std::string id;
    std::string name;
    std::string file_type; // pdf, docx, xlsx, txt or png
    ContentRule content_rule = ContentRule::bytes;
    std::int64_t stored_size = 0;
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
// without subject, mailbox or folder, from a restoretest mailbox, or with a
// received_at that isn't "YYYY-MM-DDTHH:MM:SSZ" or not a real date and time
// (month 13, 31 September, hour 24, second 60); a file without name, with another
// file_type or content_rule, a stored_size below 0, or a folder_path not
// starting with "/" or with a ".." segment; a SharePoint file whose site_id,
// drive_id or list_id isn't a Graph site ID, a Graph drive ID or a GUID; a
// OneDrive file without user; two names of one kind, or two subjects, equal
// but for ASCII case.
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
