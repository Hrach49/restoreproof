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
#include <string_view>
#include <vector>

namespace rp {

// The file's bytes: `too_large` when it is larger than `limit` (nothing is
// read), `unreadable` when it isn't there, isn't a file (a folder is
// `unreadable` whatever it holds, never `too_large`: verify_bundle.py's
// _read_file asks in the same order) or can't be read whole, exactly the
// size it says and nothing after, so a read that stops short and a file still
// growing are no file, never a part of one. Never throws but for no memory.
FileRead read_whole_file(const std::filesystem::path& path, std::uintmax_t limit);

// A reader of `folder`'s own files: a name that isn't a plain file name
// (rp::is_plain_file_name: no separator, no ':', not "..") or isn't UTF-8 is
// `unreadable`, so nothing outside the folder is ever opened.
FileReader folder_reader(std::filesystem::path folder);

// `folder` as the one path its files are listed and read through: absolute and
// in Windows' extended-length form (\\?\C:\runs\one, \\?\UNC\server\share\one),
// which has no MAX_PATH. rpworker.exe has no long-path manifest, so without it
// a file whose full path is past 260 characters doesn't open, and a verifier
// would call a file that is there missing. The folder's name is read as
// Windows reads it in `folder\name`: a name of blanks or dots, or with a space
// after it, stays what it is (no such folder), never the folder above or
// beside it. A path that is already extended, or a device's, is left as it is;
// one that can't be made absolute is returned as given. Never throws but for
// no memory.
std::filesystem::path extended_folder(const std::filesystem::path& folder);

// The names of everything in `folder` (files and folders alike, not what is
// inside those), as UTF-8 and sorted by byte, or nullopt when `folder` isn't a
// folder that can be opened. Never throws but for no memory.
//
// NTFS takes a name that isn't valid UTF-16 (a surrogate without its pair).
// Such a name is listed too, never a failure: each lone surrogate becomes the
// three bytes UTF-8's scheme gives its code point (U+DC80 is ED B2 80,
// "generalised UTF-8"), so the name stays what it is, sorts by code point like
// every other name, and is no UTF-8: folder_reader reads no such file and
// path_from_utf8 refuses it. Only name_code_points reads it back.
std::optional<std::vector<std::string>> list_folder(const std::filesystem::path& folder);

// The code points of a name list_folder gave, a lone surrogate as its own code
// point (U+D800 to U+DFFF): what a line of output escapes one by one. A byte
// that is neither UTF-8 nor such a surrogate (no listed name has one) is
// U+FFFD. Never throws but for no memory.
std::u32string name_code_points(std::string_view name);

} // namespace rp
