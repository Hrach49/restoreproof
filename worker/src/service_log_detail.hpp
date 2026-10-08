#pragma once

// Internal to rpcore: the one conversion the service's log makes
// (service_log.cpp), exposed so tests can ask it about paths no test may
// create.

#include <filesystem>
#include <optional>
#include <string>

namespace rp::detail {

// `path` in the machine's ANSI code page, which is how spdlog as built takes
// a file name (the narrow CRT calls; SPDLOG_WCHAR_FILENAMES is off), or
// nullopt when the code page doesn't give the same path back: a letter it
// lacks, which Windows would otherwise replace by '?' or by a letter that
// looks like it (best fit), and the log would open in another folder.
std::optional<std::string> ansi_path(const std::filesystem::path& path);

} // namespace rp::detail
