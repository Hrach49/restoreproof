#include <rp/sample_rng.hpp>

#include <rp/sha256.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace rp::sampling {

namespace {

constexpr std::string_view kPrefix = "restoreproof/sample-v1\n";

// The first 4 bytes of SHA-256(text), big-endian: the first 8 hex digits.
std::uint32_t first_four_bytes(const std::string& text)
{
    return static_cast<std::uint32_t>(std::stoul(sha256_hex(text).substr(0, 8), nullptr, 16));
}

std::string_view to_string(Stream stream) noexcept
{
    switch (stream) {
    case Stream::browse:
        return "browse";
    case Stream::items:
        break;
    }
    return "items";
}

bool is_run_id_char(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == ':' || c == '-';
}

} // namespace

void check_run_id(std::string_view run_id)
{
    if (run_id.empty() || run_id.size() > 128 ||
        !std::all_of(run_id.begin(), run_id.end(), is_run_id_char)) {
        throw std::invalid_argument("sampler: the run ID must be 1 to 128 characters of A-Z, "
                                    "a-z, 0-9, '.', '_', ':' and '-'");
    }
}

std::uint32_t seed_from_run_id(std::string_view run_id)
{
    return first_four_bytes(std::string{kPrefix} + std::string{run_id});
}

std::string seed_hex(std::uint32_t seed)
{
    constexpr char kHex[] = "0123456789abcdef";
    std::string hex(8, '0');
    for (int i = 7; i >= 0; --i, seed >>= 4) {
        hex[static_cast<std::size_t>(i)] = kHex[seed & 0x0f];
    }
    return hex;
}

std::uint32_t stream_seed(std::uint32_t seed, connector::ItemKind kind, Stream stream)
{
    return first_four_bytes(std::string{kPrefix} + seed_hex(seed) + "\n" +
                            std::string{connector::to_string(kind)} + "\n" +
                            std::string{to_string(stream)});
}

SampleRng::SampleRng(std::uint32_t seed) : engine_(seed) {}

std::uint32_t SampleRng::next()
{
    return static_cast<std::uint32_t>(engine_());
}

std::uint32_t SampleRng::below(std::uint32_t n)
{
    if (n == 0) {
        throw std::invalid_argument("sampler: can't draw below 0");
    }
    constexpr std::uint64_t kRange = std::uint64_t{1} << 32;
    const std::uint64_t limit = kRange - kRange % n;
    for (;;) {
        const std::uint32_t x = next();
        if (x < limit) {
            return x % n;
        }
    }
}

Shuffle::Shuffle(SampleRng& rng, std::size_t n) : rng_(rng)
{
    // Checked before the vector is made: a size_t may hold more.
    if (n > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("sampler: can't shuffle more than 4294967295 items");
    }
    order_.resize(n);
    std::iota(order_.begin(), order_.end(), std::size_t{0});
}

std::optional<std::size_t> Shuffle::next()
{
    if (at_ == order_.size()) {
        return std::nullopt;
    }
    const std::size_t j = at_ + rng_.below(static_cast<std::uint32_t>(order_.size() - at_));
    std::swap(order_[at_], order_[j]);
    return order_[at_++];
}

} // namespace rp::sampling
