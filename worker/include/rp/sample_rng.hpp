#pragma once

// Portable draws for the sampler (W2.6; docs/decisions.md 2026-09-30, W2.6
// point 4). The same inputs give the same output with every compiler and
// standard library: std::mt19937's output is fixed by the standard, while
// uniform_int_distribution, std::shuffle and std::sample are not, so none of
// them is used. An auditor repeats a draw from the run ID alone.

#include <rp/connector.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace rp::sampling {

// The draw algorithm's name, recorded in the result: a change to anything
// here is "sample-v2".
inline constexpr std::string_view kAlgorithm = "sample-v1";

// 1 to 128 bytes of A-Z a-z 0-9 . _ : -, else std::invalid_argument.
void check_run_id(std::string_view run_id);

// The run's seed: the first 4 bytes, big-endian, of
// SHA-256("restoreproof/sample-v1\n" + run_id). Hashes any text; the caller
// checks it with check_run_id first.
std::uint32_t seed_from_run_id(std::string_view run_id);

// 8 lower-case hex digits, as the result records the seed.
std::string seed_hex(std::uint32_t seed);

// Each type draws from two streams: which containers and folders are looked
// into (browse) and which candidates are taken (items).
enum class Stream { browse, items };

// The first 4 bytes, big-endian, of SHA-256("restoreproof/sample-v1\n" +
// seed_hex(seed) + "\n" + kind + "\n" + stream), kind "mail", "sharepoint" or
// "onedrive" and stream "browse" or "items": so a change to one type's sample
// size never moves another type's picks.
std::uint32_t stream_seed(std::uint32_t seed, connector::ItemKind kind, Stream stream);

class SampleRng {
public:
    explicit SampleRng(std::uint32_t seed); // std::mt19937(seed), i.e. init_genrand

    // One raw output.
    std::uint32_t next();

    // Uniform in [0, n): draws x until x < 2^32 - (2^32 mod n) and returns
    // x mod n, so it always uses at least one output. n == 0 is
    // std::invalid_argument.
    std::uint32_t below(std::uint32_t n);

private:
    std::mt19937 engine_;
};

// A lazy Fisher-Yates over [0, n): step i draws j = i + below(n - i), swaps
// order[i] and order[j] and yields order[i]; nullopt once all n have been
// yielded. Draws only as many times as next() is called. n above 2^32 - 1 is
// std::invalid_argument.
class Shuffle {
public:
    Shuffle(SampleRng& rng, std::size_t n);

    std::optional<std::size_t> next();

private:
    SampleRng& rng_;
    std::vector<std::size_t> order_;
    std::size_t at_ = 0;
};

} // namespace rp::sampling
