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
    // W4.6: the move replaces a file already at the path
    // (MOVEFILE_REPLACE_EXISTING), whole or not at all: the outbox's
    // manifest.json, the one file it rewrites. False, the default: never over
    // a file that is there.
    bool replace = false;
};

// Whether `name` is a plain Windows file name: not empty, not "." or "..",
// no control character or any of < > : " / \ | ? *, not ending in '.' or
// ' ', and not a DOS device's name. A ':' names an NTFS stream ("run.json:x"
// is a stream of run.json) and the others are names Windows refuses. Win32
// strips a trailing '.' or ' ' ("run.json." is run.json). A device's name is
// CON, PRN, AUX, NUL, CONIN$, CONOUT$, or COM or LPT and one digit 0 to 9 or
// a superscript 1, 2 or 3, in any ASCII case, as the whole name or before
// its first '.' (spaces before that '.' ignored): on Windows 10 "PRN.json" is
// the printer, and Win32 says "not found" for a device that isn't there. The
// one rule of the writer and of `test --json`'s check (W3.6 review, PR #153
// review).
bool is_plain_file_name(std::wstring_view name) noexcept;

// Why `path` can't take a new file now, or ok.
enum class NewFileCheck { ok, not_a_file_name, exists, no_folder, cannot_write };

// Whether write_file_atomically could write `path` now, in this order: its
// file name plain (above); nothing there (anything but a clean "not found",
// so a file it may not read counts); its folder there ("." for a bare name);
// and the writer's own first step done: a temp file "<path>.<16 hex>.tmp"
// made by CreateFileW with CREATE_NEW, as the writer makes it, but with
// FILE_FLAG_DELETE_ON_CLOSE, so it is gone once closed. That last step finds
// up front what the writer would only find at the end: a folder it may not
// write to, a read-only volume, a name or a path too long once the temp's 21
// characters are added. `options.temp_suffix` as the writer's (before_move
// isn't used). Never throws.
NewFileCheck check_new_file(const std::filesystem::path& path,
                            const AtomicWriteOptions& options = {}) noexcept;

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
