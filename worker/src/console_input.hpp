#pragma once

// A secret typed at the console or piped in (W4.5, `rpworker vault set`): one
// line from stdin, read without echo when stdin is a console, and never from
// an argument. Not strict: the console's own calls (ReadConsoleW with echo
// off) can't be driven by a test; the piped path is run by the exe tests.

#include <cstddef>
#include <string>
#include <string_view>

namespace rp {

enum class SecretLineState {
    ok,
    empty,       // nothing before the line's end (or the end of the input)
    too_long,    // more than max_bytes (as UTF-8) before the line's end
    not_unicode, // a console line that isn't valid UTF-16 (a lone surrogate)
    not_utf8,    // a piped line that isn't valid UTF-8
    failed       // the handle couldn't be read
};

struct SecretLine {
    SecretLineState state = SecretLineState::failed;
    std::string value; // UTF-8, the line without its "\n" or "\r\n"
};

// Reads one line from stdin. When stdin is a console: `prompt` goes to stderr,
// the line is read with echo off (the console's mode put back after), a
// newline goes to stderr once it is read, and the line is converted to UTF-8.
// Otherwise the bytes up to the first "\n" are read as UTF-8 (a "\r" before
// it stripped too) and nothing after it. Never throws but for no memory; the
// buffers it read into are wiped.
SecretLine read_secret_line(std::string_view prompt, std::size_t max_bytes);

} // namespace rp
