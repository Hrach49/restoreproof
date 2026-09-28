#include <rp/text_v1.hpp>

#include <rp/sha256.hpp>

#include <cstddef>

namespace rp {

namespace {

constexpr std::string_view kBom = "\xEF\xBB\xBF";

void drop_trailing_blanks(std::string& text)
{
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.pop_back();
    }
}

} // namespace

std::string normalize_text_v1(std::string_view utf8)
{
    if (utf8.starts_with(kBom)) {
        utf8.remove_prefix(kBom.size());
    }
    // `out` holds the finished lines; the current line's trailing blanks are
    // popped from its end before its LF is appended, and again at the end.
    std::string out;
    out.reserve(utf8.size());
    for (std::size_t i = 0; i < utf8.size(); ++i) {
        const char c = utf8[i];
        if (c == '\r' || c == '\n') {
            if (c == '\r' && i + 1 < utf8.size() && utf8[i + 1] == '\n') {
                ++i;
            }
            drop_trailing_blanks(out);
            out += '\n';
        } else {
            out += c;
        }
    }
    drop_trailing_blanks(out);
    while (!out.empty() && out.back() == '\n') {
        out.pop_back();
    }
    return out;
}

std::string text_v1_sha256(std::string_view utf8)
{
    return sha256_hex(normalize_text_v1(utf8));
}

} // namespace rp
