#include "console_input.hpp"

#include "utf16.hpp"

#include <rp/cert_export.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace rp {

namespace {

// `text` without its trailing "\n" or "\r\n".
template <typename String>
void strip_line_end(String& text)
{
    if (!text.empty() && text.back() == '\n') {
        text.pop_back();
        if (!text.empty() && text.back() == '\r') {
            text.pop_back();
        }
    }
}

void write_err(std::string_view text)
{
    const HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written = 0;
    WriteFile(err, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
}

SecretLine from_console(HANDLE in, DWORD mode, std::string_view prompt, std::size_t max_bytes)
{
    write_err(prompt);
    // Line input (Enter ends the read) without echo; Ctrl+C still ends the
    // process. The mode is put back whatever happens.
    SetConsoleMode(in, (mode | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) & ~ENABLE_ECHO_INPUT);
    // Room for the longest value, its line end and one unit more, which shows
    // a line that is too long.
    std::wstring buffer(max_bytes + 3, L'\0');
    DWORD read = 0;
    const bool ok = ReadConsoleW(in, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr);
    SetConsoleMode(in, mode);
    write_err("\n");
    SecretLine line;
    if (!ok) {
        return line;
    }
    std::wstring text(buffer.data(), read);
    const bool ended = text.ends_with(L'\n');
    strip_line_end(text);
    std::optional<std::string> utf8 = utf16_to_utf8(text);
    if (!ended && read == buffer.size()) {
        line.state = SecretLineState::too_long;
    } else if (!utf8) {
        line.state = SecretLineState::not_unicode;
    } else if (utf8->empty()) {
        line.state = SecretLineState::empty;
    } else if (utf8->size() > max_bytes) {
        line.state = SecretLineState::too_long;
    } else {
        line.state = SecretLineState::ok;
        line.value = std::move(*utf8);
    }
    if (utf8) {
        secure_wipe(*utf8);
    }
    SecureZeroMemory(text.data(), text.size() * sizeof(wchar_t));
    SecureZeroMemory(buffer.data(), buffer.size() * sizeof(wchar_t));
    return line;
}

SecretLine from_pipe(HANDLE in, std::size_t max_bytes)
{
    std::string text;
    bool ended = false;
    bool failed = false;
    while (!ended && text.size() <= max_bytes + 2) {
        char byte = '\0';
        DWORD read = 0;
        if (!ReadFile(in, &byte, 1, &read, nullptr)) {
            // A closed pipe is the end of the input, not a failure.
            failed = GetLastError() != ERROR_BROKEN_PIPE;
            break;
        }
        if (read == 0) {
            break;
        }
        text.push_back(byte);
        ended = byte == '\n';
    }
    SecretLine line;
    if (failed) {
        secure_wipe(text);
        return line;
    }
    const bool too_long = !ended && text.size() > max_bytes + 2;
    strip_line_end(text);
    if (too_long || text.size() > max_bytes) {
        line.state = SecretLineState::too_long;
    } else if (!utf8_to_utf16(text)) {
        line.state = SecretLineState::not_utf8;
    } else if (text.empty()) {
        line.state = SecretLineState::empty;
    } else {
        line.state = SecretLineState::ok;
        line.value = text;
    }
    secure_wipe(text);
    return line;
}

} // namespace

SecretLine read_secret_line(std::string_view prompt, std::size_t max_bytes)
{
    const HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (in != INVALID_HANDLE_VALUE && in != nullptr && GetConsoleMode(in, &mode)) {
        return from_console(in, mode, prompt, max_bytes);
    }
    if (in == INVALID_HANDLE_VALUE || in == nullptr) {
        return {};
    }
    return from_pipe(in, max_bytes);
}

} // namespace rp
