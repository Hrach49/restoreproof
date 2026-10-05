#pragma once

// Reading a whole file under a size limit, and a folder's files by name: the
// run folder's attachments read back before result.json is written (W4.2), and
// the files `rpworker signer verify` checks (W4.3). Outside the Signer's own
// files, which never touch the disk.

#include <rp/signer.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace rp {

// The file's bytes: `too_large` when it is larger than `limit` (nothing is
// read), `unreadable` when it isn't there or can't be read whole, exactly the
// size it says and nothing after, so a read that stops short and a file still
// growing are no file, never a part of one. Never throws but for no memory.
FileRead read_whole_file(const std::filesystem::path& path, std::uintmax_t limit);

// A reader of `folder`'s own files: a name that isn't a plain file name
// (rp::is_plain_file_name: no separator, no ':', not "..") or isn't UTF-8 is
// `unreadable`, so nothing outside the folder is ever opened.
FileReader folder_reader(std::filesystem::path folder);

// The names of everything in `folder` (files and folders alike, not what is
// inside those), as UTF-8 and sorted by byte, or nullopt when `folder` isn't a
// folder that can be opened. Never throws but for no memory.
std::optional<std::vector<std::string>> list_folder(const std::filesystem::path& folder);

} // namespace rp
