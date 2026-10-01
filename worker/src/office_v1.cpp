#include <rp/office_v1.hpp>

#include <rp/sha256.hpp>

#include <zip.h>

#include <algorithm>
#include <cstddef>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace rp {

namespace {

struct ArchiveDiscard {
    void operator()(zip_t* archive) const noexcept { zip_discard(archive); }
};
struct SourceFree {
    void operator()(zip_source_t* source) const noexcept { zip_source_free(source); }
};
struct FileClose {
    void operator()(zip_file_t* file) const noexcept { zip_fclose(file); }
};
using Archive = std::unique_ptr<zip_t, ArchiveDiscard>;
using Source = std::unique_ptr<zip_source_t, SourceFree>;
using File = std::unique_ptr<zip_file_t, FileClose>;

class ZipError {
public:
    ZipError() { zip_error_init(&error_); }
    ~ZipError() { zip_error_fini(&error_); }
    ZipError(const ZipError&) = delete;
    ZipError& operator=(const ZipError&) = delete;

    zip_error_t* get() { return &error_; }
    int code() const { return zip_error_code_zip(&error_); }

private:
    zip_error_t error_;
};

constexpr std::size_t kReadChunk = 64 * 1024;

// lab/seeder/office.py's CONTENT_FOLDERS: exact, lower-case types only.
std::string_view content_folder(std::string_view file_type)
{
    if (file_type == "docx") {
        return "word/";
    }
    if (file_type == "xlsx") {
        return "xl/";
    }
    throw OfficeContentError("office-v1 has no rule for ." + std::string{file_type} + " files");
}

[[noreturn]] void throw_not_a_zip(std::string_view file_type)
{
    throw OfficeContentError("not a ZIP package, so not a valid ." + std::string{file_type} + " file");
}

// The total-entries field of the end of central directory record, read
// before libzip allocates its directory: the last "PK\x05\x06" with a whole
// 22-byte record after it, within the last 65,557 bytes (the record and the
// longest comment), searched backwards as Python's zipfile does. nullopt when
// there is none: libzip then refuses the package. A ZIP64 package says 0xFFFF
// here.
std::optional<std::uint64_t> declared_entries(std::string_view bytes)
{
    constexpr std::size_t kRecord = 22;
    constexpr std::size_t kSearch = kRecord + 0xFFFF;
    if (bytes.size() < kRecord) {
        return std::nullopt;
    }
    const std::size_t lowest = bytes.size() > kSearch ? bytes.size() - kSearch : 0;
    for (std::size_t at = bytes.size() - kRecord + 1; at-- > lowest;) {
        if (bytes.substr(at, 4) == std::string_view{"PK\x05\x06", 4}) {
            const auto byte = [&](std::size_t i) {
                return static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[at + i]));
            };
            return byte(10) | (byte(11) << 8);
        }
    }
    return std::nullopt;
}

[[noreturn]] void throw_too_many(std::uint64_t count, const OfficeLimits& limits)
{
    throw OfficeContentError("the package has " + std::to_string(count) +
                             " entries, more than office-v1 reads (" +
                             std::to_string(limits.max_entries) + ")");
}

// The package, read-only, from its central directory. No ZIP_CHECKCONS:
// lab/seeder/office.py (Python's zipfile) never compares a local header with
// its central directory entry but for a part it reads, and takes bytes after
// the end record, so a check here could refuse a package Python hashes. A
// name stored twice stays in libzip's list without it: refuse_doubled refuses
// it. The entry count is checked before libzip allocates the directory.
Archive open_package(std::string_view bytes, std::string_view file_type, const OfficeLimits& limits)
{
    if (bytes.empty()) {
        throw_not_a_zip(file_type);  // libzip takes an empty buffer for an empty archive
    }
    if (const std::optional<std::uint64_t> count = declared_entries(bytes);
        count && *count > limits.max_entries) {
        throw_too_many(*count, limits);
    }
    ZipError error;
    Source source{zip_source_buffer_create(bytes.data(), bytes.size(), 0, error.get())};
    if (!source) {
        throw std::bad_alloc{};  // its only failure for a non-null buffer
    }
    zip_t* archive = zip_open_from_source(source.get(), ZIP_RDONLY, error.get());
    if (archive == nullptr) {
        throw_not_a_zip(file_type);  // the source is still ours: `source` frees it
    }
    source.release();  // the archive owns it now and frees it in zip_discard
    return Archive{archive};
}

// Every name from the central directory, in its order. Names without the UTF-8
// flag are CP437 converted to UTF-8 (ZIP_FL_ENC_STRICT), as Python's zipfile
// reads them.
std::vector<std::string> entry_names(zip_t* archive, std::uint64_t count)
{
    std::vector<std::string> names;
    names.reserve(static_cast<std::size_t>(count));
    for (zip_uint64_t i = 0; i < count; ++i) {
        const char* name = zip_get_name(archive, i, ZIP_FL_ENC_STRICT);
        if (name == nullptr) {
            throw OfficeContentError("cannot read the name of entry " + std::to_string(i) + ": " +
                                     zip_strerror(archive));
        }
        names.emplace_back(name);
    }
    return names;
}

// "part(s) stored more than once: a, b" (sorted), or nothing.
void refuse_doubled(const std::vector<std::string>& names)
{
    std::map<std::string, int> seen;
    for (const std::string& name : names) {
        ++seen[name];
    }
    std::string doubled;
    for (const auto& [name, times] : seen) {
        if (times > 1) {
            doubled += (doubled.empty() ? "" : ", ") + name;
        }
    }
    if (!doubled.empty()) {
        throw OfficeContentError("part(s) stored more than once: " + doubled);
    }
}

// One content part's uncompressed bytes, read under the limits. `total` is
// what the parts before it took. libzip checks the CRC and the declared size
// once the part is read to its end; either failing is a read error here.
std::string read_part(zip_t* archive, zip_uint64_t index, const std::string& name,
                      const OfficeLimits& limits, std::uint64_t& total)
{
    zip_stat_t stat;
    zip_stat_init(&stat);
    if (zip_stat_index(archive, index, 0, &stat) != 0) {
        throw OfficeContentError("cannot read part " + name + ": " + zip_strerror(archive));
    }
    if ((stat.valid & ZIP_STAT_ENCRYPTION_METHOD) != 0 && stat.encryption_method != ZIP_EM_NONE) {
        throw OfficeContentError("part " + name + " is encrypted");
    }
    if ((stat.valid & ZIP_STAT_COMP_METHOD) == 0 ||
        (stat.comp_method != ZIP_CM_STORE && stat.comp_method != ZIP_CM_DEFLATE)) {
        throw OfficeContentError("part " + name + " uses compression method " +
                                 std::to_string(stat.comp_method) +
                                 "; office-v1 reads stored and deflated parts only");
    }
    const std::string too_large = "part " + name + " is larger than office-v1 reads (" +
                                  std::to_string(limits.max_part_bytes) + " bytes)";
    const std::string too_much = "the content parts are larger than office-v1 reads (" +
                                 std::to_string(limits.max_total_bytes) + " bytes)";
    if ((stat.valid & ZIP_STAT_SIZE) != 0) {
        if (stat.size > limits.max_part_bytes) {
            throw OfficeContentError(too_large);
        }
        if (stat.size > limits.max_total_bytes - total) {  // total never passes the cap
            throw OfficeContentError(too_much);
        }
    }

    File file{zip_fopen_index(archive, index, 0)};
    if (!file) {
        throw OfficeContentError("cannot read part " + name + ": " + zip_strerror(archive));
    }
    std::string part;
    std::string chunk(kReadChunk, '\0');
    for (;;) {
        const zip_int64_t got = zip_fread(file.get(), chunk.data(), chunk.size());
        if (got < 0) {
            throw OfficeContentError("cannot read part " + name + ": " + zip_file_strerror(file.get()));
        }
        if (got == 0) {
            break;
        }
        const auto n = static_cast<std::uint64_t>(got);
        if (n > limits.max_part_bytes - part.size()) {
            throw OfficeContentError(too_large);
        }
        if (n > limits.max_total_bytes - total) {
            throw OfficeContentError(too_much);
        }
        part.append(chunk.data(), static_cast<std::size_t>(n));
        total += n;
    }
    // libzip checks the CRC over what it read but not the declared size.
    // Python's zipfile reads at most the declared size and checks the CRC over
    // that: a part holding more fails there (its CRC is of the whole part), a
    // part holding less is read whole and passes. So only more is refused.
    if ((stat.valid & ZIP_STAT_SIZE) != 0 && part.size() > stat.size) {
        throw OfficeContentError("part " + name + " holds " + std::to_string(part.size()) +
                                 " bytes, more than the " + std::to_string(stat.size) +
                                 " its entry declares");
    }
    return part;
}

} // namespace

std::string office_v1_listing(std::string_view bytes, std::string_view file_type,
                              const OfficeLimits& limits)
{
    const std::string_view folder = content_folder(file_type);
    const Archive archive = open_package(bytes, file_type, limits);

    // Checked again on what libzip read: a ZIP64 directory's own count.
    const zip_int64_t count = zip_get_num_entries(archive.get(), 0);
    if (static_cast<std::uint64_t>(count) > limits.max_entries) {
        throw_too_many(static_cast<std::uint64_t>(count), limits);
    }
    const std::vector<std::string> names = entry_names(archive.get(), static_cast<std::uint64_t>(count));
    refuse_doubled(names);

    // (name, index), sorted by the name's bytes: std::string compares as
    // unsigned char, which is UTF-8 byte order.
    std::vector<std::pair<std::string, zip_uint64_t>> chosen;
    for (zip_uint64_t i = 0; i < names.size(); ++i) {
        const std::string& name = names[i];
        if (name.starts_with(folder) && name.find("_rels/") == std::string::npos && !name.ends_with('/')) {
            chosen.emplace_back(name, i);
        }
    }
    if (chosen.empty()) {
        throw OfficeContentError("no " + std::string{folder} + " parts in this ." + std::string{file_type} +
                                 " file");
    }
    std::sort(chosen.begin(), chosen.end());

    std::string lines;
    std::uint64_t total = 0;
    for (const auto& [name, index] : chosen) {
        lines += sha256_hex(read_part(archive.get(), index, name, limits, total));
        lines += "  ";
        lines += name;
        lines += '\n';
    }
    return lines;
}

std::string office_v1_sha256(std::string_view bytes, std::string_view file_type, const OfficeLimits& limits)
{
    return sha256_hex(office_v1_listing(bytes, file_type, limits));
}

} // namespace rp
