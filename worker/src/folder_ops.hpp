#pragma once

// The outbox's calls into the file system: W4.6, docs/decisions.md 2026-10-07
// point 8; one Win32 or std::filesystem call each, with nothing decided
// here. rp::Outbox (strict) takes them as rp::OutboxFiles, so its own branches
// are tested with a fake in their place.

#include <cstdint>
#include <filesystem>
#include <optional>

namespace rp {

// Windows' ERROR_NOT_SAME_DEVICE: what move_folder answers for a target on
// another volume.
inline constexpr unsigned long kNotSameVolume = 17;

// Renames the folder `from` to `to` with one MoveFileExW and no flag: never a
// copy (so both are on one volume) and never over anything at `to`. 0, or
// Windows' error code. Never throws.
unsigned long move_folder(const std::filesystem::path& from,
                          const std::filesystem::path& to) noexcept;

// The sizes of the files in `folder` and in the folders inside it, added up;
// nullopt when it can't be listed. Never throws.
std::optional<std::uintmax_t> folder_bytes(const std::filesystem::path& folder) noexcept;

// Removes `folder` and everything in it; whether nothing is there afterwards.
// Never throws.
bool remove_folder(const std::filesystem::path& folder) noexcept;

// Makes `folder` and the levels above it that aren't there; whether it is a
// folder afterwards. Never throws.
bool make_folder(const std::filesystem::path& folder) noexcept;

// make_folder with Windows' reason (W4.7, `rpworker service install`'s log
// folder): 0 when `folder` is a folder afterwards, else the error code of the
// level that couldn't be made, or 267 (the directory name is invalid) when
// something that is no folder is there and nothing else was said. Never
// throws.
unsigned long make_folder_error(const std::filesystem::path& folder) noexcept;

// The full path of the executable this process runs (W4.7: what the
// service's command line names). Throws std::system_error when Windows can't
// say.
std::filesystem::path own_executable_path();

// Whether `a` and `b` are on one volume, so a rename between them is a rename
// and never a copy: by the mount point each is under (GetVolumePathNameW: C:\,
// or a folder a volume is mounted at), compared without regard to case or to
// the extended-length prefix. Neither path need exist yet. nullopt when it
// can't be told (a drive that isn't there); never a refusal on a guess. Never
// throws.
std::optional<bool> same_volume(const std::filesystem::path& a,
                                const std::filesystem::path& b) noexcept;

enum class PathKind { none, folder, file };

// What is at `path`: nothing (or nothing that can be asked about), a folder,
// or anything else. Never throws.
PathKind path_kind(const std::filesystem::path& path) noexcept;

} // namespace rp
