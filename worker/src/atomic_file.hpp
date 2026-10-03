#pragma once

// Writing a file whole or not at all, never over one already there (W3.6
// point 5: `rpworker test --json <file>`; docs/decisions.md 2026-10-03, W3.6).

#include <filesystem>
#include <functional>
#include <string>
#include <string_view>

namespace rp {

struct AtomicWriteOptions {
    // The temp file's 16 hex digits; null = 16 random ones (std::random_device).
    std::function<std::string()> temp_suffix;
    // Called once the temp file is written, flushed and closed, just before
    // the move; null = nothing. For the tests: a file that appears there.
    std::function<void()> before_move;
};

// Whether `name` is a plain Windows file name: not empty, not "." or "..",
// and no control character or any of < > : " / \ | ? *. A ':' names an NTFS
// stream ("run.json:x" is a stream of run.json), and the others are names
// Windows refuses. The one rule of the writer and of `test --json`'s check
// (W3.6 review).
bool is_plain_file_name(std::wstring_view name) noexcept;

// Writes `content` to `path`, never replacing what is there. A `path` whose
// file name isn't plain (above) is refused before anything is opened. In this
// order:
// a temp file beside it, "<path>.<16 hex>.tmp" (never a name from the content
// or a run ID: a ':' would name an NTFS stream), opened by CreateFileW with
// CREATE_NEW; `content` written; FlushFileBuffers; closed; then MoveFileExW
// onto `path` with MOVEFILE_WRITE_THROUGH and without
// MOVEFILE_REPLACE_EXISTING, so a file that appeared at `path` since the
// caller looked is never overwritten. The path goes through the wide API, as
// given. On any failure the temp file is deleted (a temp name already taken
// is left alone: it isn't ours). Returns whether `path` now holds `content`.
// Never throws.
bool write_file_atomically(const std::filesystem::path& path, std::string_view content,
                           const AtomicWriteOptions& options = {}) noexcept;

} // namespace rp
