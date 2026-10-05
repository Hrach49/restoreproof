#include "file_read.hpp"

#include "atomic_file.hpp"
#include "path_utf8.hpp"

#include <algorithm>
#include <fstream>
#include <system_error>
#include <utility>

namespace rp {

FileRead read_whole_file(const std::filesystem::path& path, std::uintmax_t limit)
{
    std::error_code ec;
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

std::optional<std::vector<std::string>> list_folder(const std::filesystem::path& folder)
{
    std::error_code ec;
    std::filesystem::directory_iterator entry(folder, ec);
    if (ec) {
        return std::nullopt;
    }
    std::vector<std::string> names;
    for (; entry != std::filesystem::directory_iterator{}; entry.increment(ec)) {
        names.push_back(path_to_utf8(entry->path().filename()));
    }
    if (ec) {
        return std::nullopt;
    }
    std::sort(names.begin(), names.end());
    return names;
}

} // namespace rp
