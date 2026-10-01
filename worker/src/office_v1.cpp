#include <rp/office_v1.hpp>

#include <rp/sha256.hpp>

#include <zip.h>

#include <algorithm>
#include <cstddef>
#include <map>
#include <memory>
#include <new>
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

// Opens `bytes` read-only. With `check_consistency`, libzip also compares every
// local header with its central directory entry and refuses a name stored twice
// (ZIP_ER_EXISTS); without it, it only reads the central directory. Returns
// nullptr and the error code when it can't open the package.
Archive open_archive(std::string_view bytes, bool check_consistency, int& error_code)
{
    ZipError error;
    Source source{zip_source_buffer_create(bytes.data(), bytes.size(), 0, error.get())};
    if (!source) {
        throw std::bad_alloc{};  // its only failure for a non-null buffer
    }
    const int flags = ZIP_RDONLY | (check_consistency ? ZIP_CHECKCONS : 0);
    zip_t* archive = zip_open_from_source(source.get(), flags, error.get());
    if (archive == nullptr) {
        error_code = error.code();
        return nullptr;  // the source is still ours: `source` frees it
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

// The package, consistency-checked. A name stored twice is told apart from
// any other inconsistency by reopening without the check, which allows it.
Archive open_package(std::string_view bytes, std::string_view file_type)
{
    if (bytes.empty()) {
        throw_not_a_zip(file_type);  // libzip takes an empty buffer for an empty archive
    }
    int code = ZIP_ER_OK;
    Archive archive = open_archive(bytes, true, code);
    if (archive) {
        return archive;
    }
    if (code == ZIP_ER_EXISTS) {
        int unused = ZIP_ER_OK;
        if (Archive lenient = open_archive(bytes, false, unused)) {
            const zip_int64_t count = zip_get_num_entries(lenient.get(), 0);
            refuse_doubled(entry_names(lenient.get(), static_cast<std::uint64_t>(count)));
        }
    }
    throw_not_a_zip(file_type);
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
    // libzip checks the CRC but not a deflated part's declared size; Python's
    // zipfile reads exactly that many bytes, so a part that lies fails there.
    if ((stat.valid & ZIP_STAT_SIZE) != 0 && part.size() != stat.size) {
        throw OfficeContentError("part " + name + " holds " + std::to_string(part.size()) +
                                 " bytes, not the " + std::to_string(stat.size) + " its entry declares");
    }
    return part;
}

} // namespace

std::string office_v1_listing(std::string_view bytes, std::string_view file_type,
                              const OfficeLimits& limits)
{
    const std::string_view folder = content_folder(file_type);
    const Archive archive = open_package(bytes, file_type);

    const zip_int64_t count = zip_get_num_entries(archive.get(), 0);
    if (static_cast<std::uint64_t>(count) > limits.max_entries) {
        throw OfficeContentError("the package has " + std::to_string(count) +
                                 " entries, more than office-v1 reads (" +
                                 std::to_string(limits.max_entries) + ")");
    }
    const std::vector<std::string> names = entry_names(archive.get(), static_cast<std::uint64_t>(count));
    refuse_doubled(names);  // libzip already refused one with the check; kept for the rule's sake

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
