#include "file_read.hpp"

#include "atomic_file.hpp"
#include "path_utf8.hpp"

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <system_error>
#include <utility>

namespace rp {

FileRead read_whole_file(const std::filesystem::path& path, std::uintmax_t limit)
{
    std::error_code ec;
    // A file only, and asked first: a folder has a size too (on NTFS its
    // index's), which would be held against the limit and called too large.
    if (!std::filesystem::is_regular_file(path, ec)) {
        return {};
    }
    const std::uintmax_t size = std::filesystem::file_size(path, ec);
    if (ec) {
        return {};
    }
    if (size > limit) {
        return {FileState::too_large, {}};
    }
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return {};
    }
    std::string bytes(static_cast<std::size_t>(size), '\0');
    file.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (static_cast<std::uintmax_t>(file.gcount()) != size ||
        file.peek() != std::char_traits<char>::eof()) {
        return {};
    }
    return {FileState::read, std::move(bytes)};
}

FileReader folder_reader(std::filesystem::path folder)
{
    return [folder = std::move(folder)](std::string_view name, std::uintmax_t limit) -> FileRead {
        const std::optional<std::filesystem::path> file = path_from_utf8(name);
        if (!file || !is_plain_file_name(file->native())) {
            return {};
        }
        return read_whole_file(folder / *file, limit);
    };
}

std::filesystem::path extended_folder(const std::filesystem::path& folder)
{
    constexpr std::wstring_view kExtended = LR"(\\?\)";
    constexpr std::wstring_view kDevice = LR"(\\.\)";
    constexpr std::wstring_view kShare = LR"(\\)";
    constexpr std::wstring_view kExtendedShare = LR"(\\?\UNC\)";
    // Made absolute as a file of the folder is, and the file's name taken off
    // again: Windows then reads the folder's name as it does on every open of
    // `folder\name`, where blanks and dots at its end stay. Made absolute by
    // itself it would lose them, and ` ` would be the working folder.
    std::error_code ec;
    const std::filesystem::path file = std::filesystem::absolute(folder / L"x", ec);
    if (ec || !file.has_parent_path()) {
        return folder;
    }
    const std::wstring full = file.parent_path().native();
    if (full.starts_with(kExtended) || full.starts_with(kDevice)) {
        return full;
    }
    if (full.starts_with(kShare)) {
        return std::wstring{kExtendedShare} + full.substr(kShare.size());
    }
    return std::wstring{kExtended} + full;
}

namespace {

void append_code_point(std::string& text, char32_t point)
{
    if (point < 0x80) {
        text += static_cast<char>(point);
    } else if (point < 0x800) {
        text += static_cast<char>(0xC0 | (point >> 6));
        text += static_cast<char>(0x80 | (point & 0x3F));
    } else if (point < 0x10000) {
        text += static_cast<char>(0xE0 | (point >> 12));
        text += static_cast<char>(0x80 | ((point >> 6) & 0x3F));
        text += static_cast<char>(0x80 | (point & 0x3F));
    } else {
        text += static_cast<char>(0xF0 | (point >> 18));
        text += static_cast<char>(0x80 | ((point >> 12) & 0x3F));
        text += static_cast<char>(0x80 | ((point >> 6) & 0x3F));
        text += static_cast<char>(0x80 | (point & 0x3F));
    }
}

// A file name's UTF-16 units as UTF-8; a surrogate without its pair as the
// three bytes of its own code point (see list_folder). path::u8string() would
// throw for such a name, and rp::utf16_to_utf8 has no answer for it.
std::string name_to_utf8(std::wstring_view name)
{
    std::string text;
    for (std::size_t i = 0; i < name.size(); ++i) {
        char32_t point = static_cast<char16_t>(name[i]);
        const bool high = point >= 0xD800 && point < 0xDC00;
        if (high && i + 1 < name.size()) {
            const char32_t low = static_cast<char16_t>(name[i + 1]);
            if (low >= 0xDC00 && low < 0xE000) {
                point = 0x10000 + ((point - 0xD800) << 10) + (low - 0xDC00);
                ++i;
            }
        }
        append_code_point(text, point);
    }
    return text;
}

} // namespace

std::optional<std::vector<std::string>> list_folder(const std::filesystem::path& folder)
{
    std::error_code ec;
    std::filesystem::directory_iterator entry(folder, ec);
    if (ec) {
        return std::nullopt;
    }
    std::vector<std::string> names;
    for (; entry != std::filesystem::directory_iterator{}; entry.increment(ec)) {
        names.push_back(name_to_utf8(entry->path().filename().native()));
    }
    if (ec) {
        return std::nullopt;
    }
    std::sort(names.begin(), names.end());
    return names;
}

std::u32string name_code_points(std::string_view name)
{
    constexpr char32_t kNotACharacter = 0xFFFD;
    // The smallest code point each length may hold: a shorter form exists below it.
    constexpr char32_t kSmallest[] = {0, 0x80, 0x800, 0x10000};
    std::u32string points;
    std::size_t i = 0;
    while (i < name.size()) {
        const auto lead = static_cast<unsigned char>(name[i]);
        // How many bytes follow the first, and the bits the first one carries.
        std::size_t more = 0;
        char32_t point = lead;
        if (lead >= 0xF0) {
            more = 3;
            point = lead & 0x07u;
        } else if (lead >= 0xE0) {
            more = 2;
            point = lead & 0x0Fu;
        } else if (lead >= 0xC0) {
            more = 1;
            point = lead & 0x1Fu;
        }
        // 80 to BF never starts a character, F8 and above never appear.
        bool sound = (lead < 0x80 || lead >= 0xC0) && lead < 0xF8 && name.size() - i > more;
        for (std::size_t k = 1; sound && k <= more; ++k) {
            const auto next = static_cast<unsigned char>(name[i + k]);
            sound = (next & 0xC0u) == 0x80u;
            point = (point << 6) | (next & 0x3Fu);
        }
        if (sound && point >= kSmallest[more] && point <= 0x10FFFF) {
            points += point;
            i += more + 1;
        } else {
            points += kNotACharacter;
            ++i;
        }
    }
    return points;
}

} // namespace rp
