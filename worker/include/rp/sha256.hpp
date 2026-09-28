#pragma once

// SHA-256 as the Worker writes it everywhere (W2.2): file hashes, the text-v1
// mail body hash, and later the result bundle. OpenSSL stays in the .cpp.

#include <string>
#include <string_view>

namespace rp {

// Lower-case hex SHA-256 of `bytes` (64 characters).
std::string sha256_hex(std::string_view bytes);

} // namespace rp
