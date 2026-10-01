#include <rp/office_v1.hpp>

#include <rp/sha256.hpp>

#include <nlohmann/json.hpp>
#include <zlib.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::Equals;
using Catch::Matchers::StartsWith;

namespace {

// shared/testdata/office-content-v1/: the vectors lab/tests/test_office.py
// passes too, two of them real files SharePoint rewrote.
const std::string kVectorDir = std::string{RP_SHARED_DIR} + "/testdata/office-content-v1/";

std::string read_file(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot read " + path);
    }
    return {std::istreambuf_iterator<char>(file), {}};
}

nlohmann::json load_cases()
{
    return nlohmann::json::parse(read_file(kVectorDir + "cases.json"));
}

// A ZIP package written byte by byte, so a test can make what no ZIP writer
// would: a name twice, a wrong CRC, a size that lies, an unsupported method,
// the encrypted flag.
struct Entry {
    std::string name;
    std::string data;                         // uncompressed
    bool deflate = false;                     // raw deflate (method 8), else stored (0)
    std::uint16_t flags = 0;                  // bit 0: encrypted, bit 11: UTF-8 name
    std::optional<std::uint16_t> method;      // written instead of 0/8; the data stays as compressed
    std::optional<std::uint32_t> crc;         // written instead of the real CRC-32
    std::optional<std::uint32_t> size;        // written instead of the real uncompressed size
};

std::string raw_deflate(const std::string& data)
{
    z_stream stream{};
    if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        throw std::runtime_error("deflateInit2 failed");
    }
    std::string out(deflateBound(&stream, static_cast<uLong>(data.size())), '\0');
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    stream.avail_in = static_cast<uInt>(data.size());
    stream.next_out = reinterpret_cast<Bytef*>(out.data());
    stream.avail_out = static_cast<uInt>(out.size());
    const int result = deflate(&stream, Z_FINISH);
    out.resize(stream.total_out);
    deflateEnd(&stream);
    if (result != Z_STREAM_END) {
        throw std::runtime_error("deflate failed");
    }
    return out;
}

void put16(std::string& out, std::uint32_t value)
{
    out += static_cast<char>(value & 0xFF);
    out += static_cast<char>((value >> 8) & 0xFF);
}

void put32(std::string& out, std::uint32_t value)
{
    put16(out, value & 0xFFFF);
    put16(out, value >> 16);
}

std::string build_zip(const std::vector<Entry>& entries)
{
    std::string zip;
    std::string directory;
    for (const Entry& e : entries) {
        const std::string stored = e.deflate ? raw_deflate(e.data) : e.data;
        const std::uint16_t method = e.method.value_or(e.deflate ? 8 : 0);
        const auto crc = e.crc.value_or(static_cast<std::uint32_t>(
            crc32(0, reinterpret_cast<const Bytef*>(e.data.data()), static_cast<uInt>(e.data.size()))));
        const auto size = e.size.value_or(static_cast<std::uint32_t>(e.data.size()));
        const auto offset = static_cast<std::uint32_t>(zip.size());
        // The fields local header and central directory entry share.
        std::string common;
        put16(common, 20);      // version needed: 2.0
        put16(common, e.flags);
        put16(common, method);
        put16(common, 0);       // time 00:00:00
        put16(common, 0x21);    // date 1980-01-01
        put32(common, crc);
        put32(common, static_cast<std::uint32_t>(stored.size()));
        put32(common, size);
        put16(common, static_cast<std::uint32_t>(e.name.size()));
        put16(common, 0);       // extra field length

        put32(zip, 0x04034b50);
        zip += common + e.name + stored;

        put32(directory, 0x02014b50);
        put16(directory, 20);   // version made by: 2.0, MS-DOS
        directory += common;
        put16(directory, 0);    // comment length
        put16(directory, 0);    // disk number
        put16(directory, 0);    // internal attributes
        put32(directory, 0);    // external attributes
        put32(directory, offset);
        directory += e.name;
    }
    const auto directory_offset = static_cast<std::uint32_t>(zip.size());
    zip += directory;
    put32(zip, 0x06054b50);
    put16(zip, 0);
    put16(zip, 0);
    put16(zip, static_cast<std::uint32_t>(entries.size()));
    put16(zip, static_cast<std::uint32_t>(entries.size()));
    put32(zip, static_cast<std::uint32_t>(directory.size()));
    put32(zip, directory_offset);
    put16(zip, 0);              // comment length
    return zip;
}

std::vector<Entry> stored(const std::map<std::string, std::string>& parts, bool deflate = false)
{
    std::vector<Entry> entries;
    for (const auto& [name, data] : parts) {
        entries.push_back(Entry{.name = name, .data = data, .deflate = deflate});
    }
    return entries;
}

// lab/tests/test_office.py's _hand_hash: the rule written out once more.
std::string hand_hash(const std::map<std::string, std::string>& parts)
{
    std::string lines;
    for (const auto& [name, data] : parts) {  // std::map: sorted by bytes
        lines += rp::sha256_hex(data) + "  " + name + "\n";
    }
    return rp::sha256_hex(lines);
}

std::string error_of(const std::string& bytes, const std::string& file_type, const rp::OfficeLimits& limits = {})
{
    try {
        (void)rp::office_v1_sha256(bytes, file_type, limits);
    } catch (const rp::OfficeContentError& e) {
        return e.what();
    }
    return "(no error)";
}

const std::map<std::string, std::string> kDocx = {
    {"word/document.xml", "<w:document><w:t>one</w:t></w:document>"},
    {"word/styles.xml", "<w:styles/>"},
};

} // namespace

// --- failure paths ----------------------------------------------------------

TEST_CASE("office-v1 has a rule for docx and xlsx only, in the manifest's lower case", "[office-v1]")
{
    const std::string file_type = GENERATE(as<std::string>{}, "pptx", "doc", "xlsm", "docm", "DOCX", "Xlsx", "", "pdf");
    CAPTURE(file_type);
    CHECK_THAT(error_of(build_zip(stored(kDocx)), file_type),
               Equals("office-v1 has no rule for ." + file_type + " files"));
}

TEST_CASE("bytes that are no ZIP package are refused as no valid file of their type", "[office-v1]")
{
    const std::string local = read_file(kVectorDir + "rp-canary-02.local.docx");
    const auto [what, bytes] = GENERATE_COPY(table<std::string, std::string>({
        {"empty", ""},
        {"a PDF", "%PDF-1.4 not a zip"},
        {"bytes", std::string("\x00\x01\x02\x03\xff\xfe\xfd PK\x03\x04", 12)},
        {"the first half of a real package", local.substr(0, local.size() / 2)},
        {"a real package without its last byte", local.substr(0, local.size() - 1)},
        {"an end record whose directory isn't there", [] {
             std::string zip = build_zip(stored(kDocx));
             zip[zip.size() - 3] = 0x7F;  // the directory's offset: far past the end
             return zip;
         }()},
    }));
    CAPTURE(what);
    CHECK_THAT(error_of(bytes, "docx"), Equals("not a ZIP package, so not a valid .docx file"));
    CHECK_THAT(error_of(bytes, "xlsx"), Equals("not a ZIP package, so not a valid .xlsx file"));
}

TEST_CASE("a package without content parts of its type is refused", "[office-v1]")
{
    const auto [what, file_type, parts] = GENERATE(table<std::string, std::string, std::map<std::string, std::string>>({
        {"only metadata and relationships", "docx",
         {{"docProps/core.xml", "x"}, {"word/_rels/document.xml.rels", "r"}, {"[Content_Types].xml", "c"}}},
        {"only the folder itself", "docx", {{"word/", ""}, {"word/media/", ""}}},
        {"the folder in another case", "docx", {{"Word/document.xml", "d"}, {"WORD/styles.xml", "s"}}},
        {"a docx's parts in an xlsx", "xlsx", {{"word/document.xml", "d"}}},
        {"an xlsx's parts in a docx", "docx", {{"xl/workbook.xml", "w"}}},
        {"a name that only contains the folder", "xlsx", {{"docProps/xl/workbook.xml", "w"}, {"xl", "w"}}},
        {"every part under a _rels/ folder", "xlsx", {{"xl/_rels/workbook.xml.rels", "r"}, {"xl/worksheets/_rels/sheet1.xml.rels", "r"}}},
    }));
    CAPTURE(what);
    const std::string folder = file_type == "docx" ? "word/" : "xl/";
    CHECK_THAT(error_of(build_zip(stored(parts)), file_type),
               Equals("no " + folder + " parts in this ." + file_type + " file"));
}

TEST_CASE("a part stored twice is refused, content or not, naming every such part", "[office-v1]")
{
    const auto [what, entries, message] = GENERATE(table<std::string, std::vector<Entry>, std::string>({
        {"a content part, same bytes",
         {{.name = "word/document.xml", .data = "a"}, {.name = "word/document.xml", .data = "a"}},
         "part(s) stored more than once: word/document.xml"},
        {"a content part, other bytes",
         {{.name = "word/document.xml", .data = "a"}, {.name = "word/styles.xml", .data = "s"},
          {.name = "word/document.xml", .data = "b", .deflate = true}},
         "part(s) stored more than once: word/document.xml"},
        {"metadata only",
         {{.name = "docProps/app.xml", .data = "a"}, {.name = "word/document.xml", .data = "d"},
          {.name = "docProps/app.xml", .data = "b"}},
         "part(s) stored more than once: docProps/app.xml"},
        {"two names, three times",
         {{.name = "word/styles.xml", .data = "s"}, {.name = "[Content_Types].xml", .data = "c"},
          {.name = "word/styles.xml", .data = "s"}, {.name = "[Content_Types].xml", .data = "c"},
          {.name = "word/styles.xml", .data = "s"}},
         "part(s) stored more than once: [Content_Types].xml, word/styles.xml"},
    }));
    CAPTURE(what);
    CHECK_THAT(error_of(build_zip(entries), "docx"), Equals(message));
}

TEST_CASE("a content part whose CRC-32 doesn't match its bytes is refused", "[office-v1]")
{
    const bool deflate = GENERATE(false, true);
    CAPTURE(deflate);
    std::vector<Entry> entries = stored(kDocx, deflate);
    entries[0].crc = 0x12345678;  // word/document.xml, in both headers alike
    CHECK_THAT(error_of(build_zip(entries), "docx"),
               ContainsSubstring("cannot read part word/document.xml: ") && ContainsSubstring("CRC"));
}

TEST_CASE("a deflated content part whose bytes are no deflate stream is refused", "[office-v1]")
{
    std::vector<Entry> entries = stored(kDocx);
    entries[0].method = 8;  // word/document.xml: its plain bytes, said to be deflated
    CHECK_THAT(error_of(build_zip(entries), "docx"), StartsWith("cannot read part word/document.xml: "));
}

TEST_CASE("a bad CRC outside the content parts is never read, as in the Python rule", "[office-v1]")
{
    std::vector<Entry> entries = stored(kDocx);
    entries.push_back(Entry{.name = "docProps/core.xml", .data = "p", .crc = 0x12345678});
    CHECK(rp::office_v1_sha256(build_zip(entries), "docx") == hand_hash(kDocx));
}

TEST_CASE("a content part in a method other than stored or deflate is refused", "[office-v1]")
{
    // 99 (WinZip AES) isn't here: without its extra field libzip refuses the
    // entry as it opens the package ("not a ZIP package"), which is a refusal too.
    const std::uint16_t method = GENERATE(as<std::uint16_t>{}, 1, 6, 9, 12, 14, 93, 95, 98);
    CAPTURE(method);
    std::vector<Entry> entries = stored(kDocx);
    entries[1].method = method;  // word/styles.xml
    CHECK_THAT(error_of(build_zip(entries), "docx"),
               Equals("part word/styles.xml uses compression method " + std::to_string(method) +
                      "; office-v1 reads stored and deflated parts only"));
}

TEST_CASE("an encrypted content part is refused", "[office-v1]")
{
    const bool deflate = GENERATE(false, true);
    CAPTURE(deflate);
    std::vector<Entry> entries = stored(kDocx, deflate);
    entries[0].flags = 0x0001;  // traditional PKWARE encryption
    if (!deflate) {
        // A stored encrypted part is its 12-byte encryption header and its
        // bytes; libzip refuses one whose sizes say otherwise as it opens.
        entries[0].size = static_cast<std::uint32_t>(entries[0].data.size());
        entries[0].data = std::string(12, 'h') + entries[0].data;
    }
    CHECK_THAT(error_of(build_zip(entries), "docx"), Equals("part word/document.xml is encrypted"));
}

TEST_CASE("a part's declared size over the limits is refused before it is read", "[office-v1]")
{
    const std::map<std::string, std::string> parts = {
        {"xl/workbook.xml", std::string(40, 'w')}, {"xl/worksheets/sheet1.xml", std::string(40, 's')}};
    const auto [what, limits, message] = GENERATE(table<std::string, rp::OfficeLimits, std::string>({
        {"one part", {.max_part_bytes = 39, .max_total_bytes = 1000, .max_entries = 10},
         "part xl/workbook.xml is larger than office-v1 reads (39 bytes)"},
        {"all parts", {.max_part_bytes = 40, .max_total_bytes = 79, .max_entries = 10},
         "the content parts are larger than office-v1 reads (79 bytes)"},
    }));
    CAPTURE(what);
    const bool deflate = GENERATE(false, true);
    CAPTURE(deflate);
    CHECK_THAT(error_of(build_zip(stored(parts, deflate)), "xlsx", limits), Equals(message));
    // At the limits exactly, the package passes.
    const rp::OfficeLimits enough{.max_part_bytes = 40, .max_total_bytes = 80, .max_entries = 2};
    CHECK(rp::office_v1_sha256(build_zip(stored(parts, deflate)), "xlsx", enough) == hand_hash(parts));
}

TEST_CASE("a deflated part that inflates past the limits is refused while it is read", "[office-v1]")
{
    // The sizes lie: each part claims 10 bytes and inflates to 40,000 (a zip bomb in small).
    const std::string big(40000, 'b');
    const auto [what, limits, message] = GENERATE_COPY(table<std::string, rp::OfficeLimits, std::string>({
        {"one part", {.max_part_bytes = 1000, .max_total_bytes = 100000, .max_entries = 10},
         "part xl/workbook.xml is larger than office-v1 reads (1000 bytes)"},
        {"all parts", {.max_part_bytes = 50000, .max_total_bytes = 1000, .max_entries = 10},
         "the content parts are larger than office-v1 reads (1000 bytes)"},
    }));
    CAPTURE(what);
    const std::vector<Entry> entries = {
        {.name = "xl/workbook.xml", .data = big, .deflate = true, .size = 10},
        {.name = "xl/worksheets/sheet1.xml", .data = big, .deflate = true, .size = 10}};
    CHECK_THAT(error_of(build_zip(entries), "xlsx", limits), Equals(message));
}

TEST_CASE("all parts together past the total limit are refused while they are read", "[office-v1]")
{
    // The first part is honest; the second claims 10 bytes and holds 4,000.
    const std::vector<Entry> entries = {
        {.name = "xl/a.xml", .data = std::string(4000, 'a'), .deflate = true},
        {.name = "xl/b.xml", .data = std::string(4000, 'b'), .deflate = true, .size = 10}};
    const rp::OfficeLimits limits{.max_part_bytes = 5000, .max_total_bytes = 6000, .max_entries = 10};
    CHECK_THAT(error_of(build_zip(entries), "xlsx", limits),
               Equals("the content parts are larger than office-v1 reads (6000 bytes)"));
}

TEST_CASE("a part that holds more than it declares is refused, the limits aside", "[office-v1]")
{
    // libzip checks the CRC over what it read but not a deflated part's
    // declared size; Python's zipfile reads at most the declared size, so its
    // CRC fails on such a part (verified on these bytes with
    // lab/seeder/office.py: "Bad CRC-32 for file 'word/document.xml'").
    const std::string actual = std::to_string(kDocx.at("word/document.xml").size());
    std::vector<Entry> entries = stored(kDocx, true);
    entries[0].size = 10;
    CHECK_THAT(error_of(build_zip(entries), "docx"),
               Equals("part word/document.xml holds " + actual + " bytes, more than the 10 its entry declares"));
}

TEST_CASE("a deflated part that holds less than it declares is read whole, as in Python", "[office-v1]")
{
    // Python's zipfile stops at the end of the deflate stream and checks the
    // CRC over what it read, which matches: lab/seeder/office.py hashed these
    // bytes (Python 3.12.9) to the hash below.
    std::vector<Entry> entries = stored(kDocx, true);
    entries[0].size = 100000;
    const std::string zip = build_zip(entries);
    CHECK(rp::office_v1_sha256(zip, "docx") == hand_hash(kDocx));
    CHECK(rp::office_v1_sha256(zip, "docx") == "95c1729b936aa1bd114751e7c71fedab8aff419fe1611d9794e176405fccf800");
}

TEST_CASE("a stored part whose sizes differ is refused as it is read", "[office-v1]")
{
    // libzip refuses it on reading. Python refuses one declaring less (bad
    // CRC) but reads one declaring more; no Office writer makes either
    // (lab/README.md, "The C++ checker also refuses").
    const std::uint32_t declared = GENERATE(10u, 100000u);
    CAPTURE(declared);
    std::vector<Entry> entries = stored(kDocx);
    entries[0].size = declared;
    CHECK_THAT(error_of(build_zip(entries), "docx"), StartsWith("cannot read part word/document.xml: "));
}

TEST_CASE("a local header that disagrees with its directory entry, or bytes after the end record, "
          "hash as in Python",
          "[office-v1]")
{
    // Python's zipfile reads the central directory, compares a local header
    // only with a part it reads (and only its name), and takes bytes after the
    // end record. Each package below was hashed by lab/seeder/office.py
    // (Python 3.12.9) to the hash at the end.
    std::vector<Entry> with_props = stored(kDocx);
    with_props.insert(with_props.begin(), Entry{.name = "docProps/core.xml", .data = "props"});
    const auto [what, zip] = GENERATE_COPY(table<std::string, std::string>({
        {"a metadata part's local method", [&] {
             std::string zip = build_zip(with_props);
             zip[8] = 0x08;  // docProps/core.xml's local header: deflate, not stored
             return zip;
         }()},
        {"a metadata part's local name", [&] {
             std::string zip = build_zip(with_props);
             zip[30] = 'D';  // docProps/core.xml's local header: DocProps/core.xml
             return zip;
         }()},
        {"a content part's local method", [] {
             std::string zip = build_zip(stored(kDocx));
             zip[8] = 0x08;  // word/document.xml's local header: deflate; its entry says stored
             return zip;
         }()},
        {"bytes after the end record", build_zip(stored(kDocx)) + "trailing bytes after the end record"},
    }));
    CAPTURE(what);
    CHECK(rp::office_v1_sha256(zip, "docx") == hand_hash(kDocx));
    CHECK(rp::office_v1_sha256(zip, "docx") == "95c1729b936aa1bd114751e7c71fedab8aff419fe1611d9794e176405fccf800");
}

TEST_CASE("a content part's local header naming it otherwise is read by its directory name", "[office-v1]")
{
    // Less strict than Python, which refuses it ("File name in directory
    // 'word/document.xml' and header b'Word/document.xml' differ"): libzip
    // reads a local header's lengths only. The bytes hashed are the part's
    // own, so it can't pass a changed part.
    std::string zip = build_zip(stored(kDocx));
    zip[30] = 'W';
    CHECK(rp::office_v1_sha256(zip, "docx") == hand_hash(kDocx));
}

TEST_CASE("a package whose end record declares more entries than the limit is refused before "
          "libzip reads its directory",
          "[office-v1]")
{
    // The directory holds 2 entries: libzip would refuse the package as no ZIP;
    // the refusal names the count, so the end record was read first.
    const auto [what, declared, trailing] = GENERATE(table<std::string, std::uint32_t, std::string>({
        {"10,001", 10001, ""},
        {"60,000", 60000, ""},
        {"ZIP64's marker", 0xFFFF, ""},
        {"60,000, bytes after the end record", 60000, std::string(100, '\0') + "PK\x05"},
    }));
    CAPTURE(what);
    std::string zip = build_zip(stored(kDocx));
    const std::size_t end = zip.size() - 22;
    zip[end + 8] = zip[end + 10] = static_cast<char>(declared & 0xFF);
    zip[end + 9] = zip[end + 11] = static_cast<char>(declared >> 8);
    CHECK_THAT(error_of(zip + trailing, "docx"),
               Equals("the package has " + std::to_string(declared) + " entries, more than office-v1 reads (10000)"));
}

TEST_CASE("a package with more entries than the limit is refused", "[office-v1]")
{
    const std::map<std::string, std::string> parts = {
        {"word/document.xml", "d"}, {"docProps/core.xml", "p"}, {"[Content_Types].xml", "c"}};
    const rp::OfficeLimits two{.max_entries = 2};
    CHECK_THAT(error_of(build_zip(stored(parts)), "docx", two),
               Equals("the package has 3 entries, more than office-v1 reads (2)"));
    const rp::OfficeLimits three{.max_entries = 3};
    CHECK(rp::office_v1_sha256(build_zip(stored(parts)), "docx", three) == hand_hash({{"word/document.xml", "d"}}));
}

TEST_CASE("the default limits are 64 MiB per part and in all, and 10,000 entries", "[office-v1]")
{
    const rp::OfficeLimits limits;
    CHECK(limits.max_part_bytes == 64ULL * 1024 * 1024);
    CHECK(limits.max_total_bytes == 64ULL * 1024 * 1024);
    CHECK(limits.max_entries == 10000);
    CHECK(rp::kOfficeV1 == "office-v1");
}

// --- the shared vectors: real SharePoint rewrites ---------------------------

TEST_CASE("every shared office-v1 vector hashes as the seeder's", "[office-v1]")
{
    const nlohmann::json vectors = load_cases();
    REQUIRE(vectors.at("rule").get<std::string>() == rp::kOfficeV1);
    const nlohmann::json& cases = vectors.at("cases");
    REQUIRE(cases.size() == 4);
    for (const nlohmann::json& c : cases) {
        const std::string file = c.at("file").get<std::string>();
        CAPTURE(file);
        const std::string bytes = read_file(kVectorDir + file);
        CHECK(rp::office_v1_sha256(bytes, c.at("file_type").get<std::string>()) ==
              c.at("content_sha256").get<std::string>());
    }
}

TEST_CASE("SharePoint's rewrite of a canary keeps its office-v1 hash", "[office-v1]")
{
    const auto [stem, file_type] = GENERATE(table<std::string, std::string>({
        {"rp-canary-02", "docx"}, {"rp-canary-03", "xlsx"}}));
    CAPTURE(stem);
    const std::string local = read_file(kVectorDir + stem + ".local." + file_type);
    const std::string rewritten = read_file(kVectorDir + stem + ".sharepoint." + file_type);
    REQUIRE(local != rewritten);  // SharePoint really did rewrite the package
    CHECK(rp::office_v1_listing(local, file_type) == rp::office_v1_listing(rewritten, file_type));
    CHECK(rp::office_v1_sha256(local, file_type) == rp::office_v1_sha256(rewritten, file_type));
    // The other type's rule finds none of its parts.
    const std::string other = file_type == "docx" ? "xlsx" : "docx";
    CHECK_THAT(error_of(local, other), ContainsSubstring("parts in this ." + other + " file"));
}

// --- the rule -----------------------------------------------------------------

TEST_CASE("the hash is the SHA-256 of the sorted listing, the other parts left out", "[office-v1]")
{
    const std::map<std::string, std::string> parts = {
        {"word/styles.xml", "s"}, {"word/document.xml", "d"}, {"word/media/image1.png", "\x89PNG"}};
    const std::map<std::string, std::string> ignored = {
        {"[Content_Types].xml", "c"}, {"_rels/.rels", "r"}, {"word/_rels/document.xml.rels", "r2"},
        {"docProps/core.xml", "p"}, {"docProps/custom.xml", "q"}, {"customXml/item1.xml", "x"},
        {"[trash]/0000.dat", "t"}, {"word/", ""}, {"xl/workbook.xml", "w"}};
    std::vector<Entry> entries;
    // Out of order on purpose, ignored parts in between.
    for (const auto& [name, data] : ignored) {
        entries.push_back(Entry{.name = name, .data = data});
        if (name == "_rels/.rels") {
            entries.push_back(Entry{.name = "word/styles.xml", .data = "s", .deflate = true});
            entries.push_back(Entry{.name = "word/media/image1.png", .data = "\x89PNG"});
        }
    }
    entries.push_back(Entry{.name = "word/document.xml", .data = "d"});
    const std::string zip = build_zip(entries);

    CHECK(rp::office_v1_sha256(zip, "docx") == hand_hash(parts));
    CHECK(rp::office_v1_listing(zip, "docx") ==
          rp::sha256_hex("d") + "  word/document.xml\n" +
          rp::sha256_hex("\x89PNG") + "  word/media/image1.png\n" +
          rp::sha256_hex("s") + "  word/styles.xml\n");
}

TEST_CASE("stored and deflated parts give the same hash", "[office-v1]")
{
    const std::map<std::string, std::string> parts = {
        {"xl/workbook.xml", std::string(500, 'w')}, {"xl/worksheets/sheet1.xml", std::string(500, 's')}};
    const std::string as_stored = build_zip(stored(parts, false));
    const std::string as_deflated = build_zip(stored(parts, true));
    REQUIRE(as_stored != as_deflated);
    REQUIRE(as_deflated.size() < as_stored.size());
    CHECK(rp::office_v1_sha256(as_stored, "xlsx") == hand_hash(parts));
    CHECK(rp::office_v1_sha256(as_deflated, "xlsx") == hand_hash(parts));
}

TEST_CASE("a changed, added or removed content part changes the hash", "[office-v1]")
{
    const std::string before = rp::office_v1_sha256(build_zip(stored(kDocx, true)), "docx");
    auto parts = kDocx;
    const std::string what = GENERATE(as<std::string>{}, "changed", "added", "removed", "renamed");
    CAPTURE(what);
    if (what == "changed") {
        parts["word/document.xml"] = "<w:document><w:t>two</w:t></w:document>";
    } else if (what == "added") {
        parts["word/media/image1.png"] = "png";
    } else if (what == "removed") {
        parts.erase("word/styles.xml");
    } else {
        parts["word/Styles.xml"] = parts["word/styles.xml"];
        parts.erase("word/styles.xml");
    }
    CHECK(rp::office_v1_sha256(build_zip(stored(parts, true)), "docx") != before);
}

TEST_CASE("a change outside the content parts leaves the hash alone", "[office-v1]")
{
    const std::string name = GENERATE(as<std::string>{}, "[Content_Types].xml", "_rels/.rels",
                                      "word/_rels/document.xml.rels", "word/glossary/_rels/document.xml.rels",
                                      "docProps/core.xml", "docProps/custom.xml", "customXml/item1.xml",
                                      "customXml/_rels/item1.xml.rels", "[trash]/0000.dat", "xl/styles.xml",
                                      "Word/document.xml", "word/media/");
    CAPTURE(name);
    auto with = stored(kDocx);
    with.push_back(Entry{.name = name, .data = "before"});
    auto changed = stored(kDocx);
    changed.push_back(Entry{.name = name, .data = "after, and longer", .deflate = true});
    CHECK(rp::office_v1_sha256(build_zip(with), "docx") == hand_hash(kDocx));
    CHECK(rp::office_v1_sha256(build_zip(changed), "docx") == hand_hash(kDocx));
}

TEST_CASE("names sort by their UTF-8 bytes, and a name without the UTF-8 flag is read as CP437", "[office-v1]")
{
    // Upper case before lower, ASCII before any multibyte character; 0x82 is
    // CP437's e-acute, which Python's zipfile and libzip both turn into U+00E9.
    const std::vector<Entry> entries = {
        {.name = "word/media/caf\x82.bin", .data = "cp437", .deflate = true},
        {.name = "word/media/\xc3\xa9t\xc3\xa9.bin", .data = "utf-8", .flags = 0x0800},
        {.name = "word/media/z.bin", .data = "z"},
        {.name = "word/Media/a.bin", .data = "A"},
        {.name = "word/document.xml", .data = std::string(300, 'd'), .deflate = true},
        {.name = "docProps/app.xml", .data = "app"},
    };
    const std::string zip = build_zip(entries);
    CHECK(rp::office_v1_listing(zip, "docx") ==
          rp::sha256_hex("A") + "  word/Media/a.bin\n" +
          rp::sha256_hex(std::string(300, 'd')) + "  word/document.xml\n" +
          rp::sha256_hex("cp437") + "  word/media/caf\xc3\xa9.bin\n" +
          rp::sha256_hex("z") + "  word/media/z.bin\n" +
          rp::sha256_hex("utf-8") + "  word/media/\xc3\xa9t\xc3\xa9.bin\n");
    // Computed independently by lab/seeder/office.py's office_content_sha256 on
    // exactly these bytes (written to a file once and hashed with
    // `uv run python -c "from seeder.office import office_content_sha256; ..."`).
    CHECK(rp::office_v1_sha256(zip, "docx") == "22bd42bdd340c8f417d357594a95424744130f1f1148c9b8f281d5ec333c0392");
}

