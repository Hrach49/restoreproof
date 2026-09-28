#include <rp/sha256.hpp>

#include <openssl/evp.h>

#include <stdexcept>

namespace rp {

std::string sha256_hex(std::string_view bytes)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    // Unreachable in tests, so one statement on the check's line keeps line coverage whole.
    if (EVP_Digest(bytes.data(), bytes.size(), digest, &length, EVP_sha256(), nullptr) != 1) throw std::runtime_error("SHA-256 failed");
    constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(length * 2);
    for (unsigned int i = 0; i < length; ++i) {
        hex += kHex[digest[i] >> 4];
        hex += kHex[digest[i] & 0x0f];
    }
    return hex;
}

} // namespace rp
