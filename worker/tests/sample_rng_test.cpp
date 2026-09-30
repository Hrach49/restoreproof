#include <rp/sample_rng.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

// Every golden value below was computed a second time, outside C++, by a
// Python port of init_genrand/genrand_int32 and hashlib (docs/decisions.md
// 2026-09-30, W2.6 point 4: an auditor must be able to repeat a draw anywhere).

namespace {

using rp::connector::ItemKind;
using rp::sampling::SampleRng;
using rp::sampling::Shuffle;
using rp::sampling::Stream;

constexpr std::string_view kRunIdRule =
    "sampler: the run ID must be 1 to 128 characters of A-Z, a-z, 0-9, '.', '_', ':' and '-'";

std::vector<std::size_t> drain(Shuffle& shuffle)
{
    std::vector<std::size_t> out;
    while (const std::optional<std::size_t> i = shuffle.next()) {
        out.push_back(*i);
    }
    return out;
}

} // namespace

// Failure paths first.
TEST_CASE("check_run_id refuses a run ID that isn't 1 to 128 safe ASCII characters", "[sample-rng]")
{
    const std::string run_id = GENERATE(values<std::string>({
        "",
        std::string(129, 'a'),
        "run 0001",
        "run/0001",
        "run\\0001",
        "run-\xc3\xa9",
        std::string("run\0x", 5),
        "run\n",
        "run+0001",
    }));
    CAPTURE(run_id);
    try {
        rp::sampling::check_run_id(run_id);
        FAIL("accepted");
    } catch (const std::invalid_argument& e) {
        CHECK(std::string_view{e.what()} == kRunIdRule);
    }
}

TEST_CASE("check_run_id accepts letters, digits, '.', '_', ':' and '-' up to 128", "[sample-rng]")
{
    const std::string run_id = GENERATE(values<std::string>({
        "a",
        std::string(128, 'Z'),
        "run-0001",
        "live-dry-run",
        "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
        "2026-09-30T12:00:00Z_job.7",
    }));
    CAPTURE(run_id);
    CHECK_NOTHROW(rp::sampling::check_run_id(run_id));
}

TEST_CASE("below(0) has nothing to draw", "[sample-rng]")
{
    SampleRng rng(1);
    try {
        rng.below(0);
        FAIL("drew");
    } catch (const std::invalid_argument& e) {
        CHECK(std::string_view{e.what()} == "sampler: can't draw below 0");
    }
}

TEST_CASE("a Shuffle of more than 2^32 - 1 items is refused before anything is allocated",
          "[sample-rng]")
{
    if constexpr (sizeof(std::size_t) > sizeof(std::uint32_t)) {
        SampleRng rng(1);
        const std::size_t n = GENERATE(std::size_t{1} << 32, std::numeric_limits<std::size_t>::max());
        try {
            Shuffle shuffle(rng, n);
            FAIL("made");
        } catch (const std::invalid_argument& e) {
            CHECK(std::string_view{e.what()} == "sampler: can't shuffle more than 4294967295 items");
        }
    } else {
        SUCCEED("size_t holds no more than 2^32 - 1");
    }
}

// n = 2^31 + 1 accepts only outputs below 2^32 - (2^32 mod n) = 2^31 + 1, so
// about half are rejected. The seed is searched for, not assumed: the first
// whose first output is rejected and second accepted (3, in the Python port).
TEST_CASE("below rejects an output at or above the last whole multiple of n", "[sample-rng]")
{
    constexpr std::uint32_t n = (std::uint32_t{1} << 31) + 1;
    constexpr std::uint64_t limit = (std::uint64_t{1} << 32) - ((std::uint64_t{1} << 32) % n);
    STATIC_REQUIRE(limit == n);
    std::uint32_t seed = 0;
    std::uint32_t first = 0;
    std::uint32_t second = 0;
    std::uint32_t third = 0;
    for (;; ++seed) {
        std::mt19937 engine(seed);
        first = static_cast<std::uint32_t>(engine());
        second = static_cast<std::uint32_t>(engine());
        third = static_cast<std::uint32_t>(engine());
        if (first >= limit && second < limit) {
            break;
        }
    }
    CHECK(seed == 3);
    CHECK(first == 2365658986u);
    CHECK(second == 303761048u);

    SampleRng rng(seed);
    CHECK(rng.below(n) == second % n);
    // Exactly two outputs were used: the next raw one is the third.
    CHECK(rng.next() == third);
    CHECK(third == 3041471737u);
}

TEST_CASE("below always uses at least one output, even with one value to pick", "[sample-rng]")
{
    SampleRng rng(0x63acfd62);
    CHECK(rng.below(1) == 0);
    CHECK(rng.next() == 762822402u); // the second output

    // A power of two rejects nothing: 2^32 mod 2^31 is 0.
    SampleRng power(0x63acfd62);
    CHECK(power.below(std::uint32_t{1} << 31) == 4273894158u % (std::uint32_t{1} << 31));
    CHECK(power.next() == 762822402u);

    SampleRng widest(0x63acfd62);
    CHECK(widest.below(std::numeric_limits<std::uint32_t>::max()) == 4273894158u);
}

TEST_CASE("SampleRng is std::mt19937: the standard's check value", "[sample-rng]")
{
    SampleRng rng(5489);
    std::uint32_t last = 0;
    for (int i = 0; i < 10000; ++i) {
        last = rng.next();
    }
    CHECK(last == 4123659995u);
}

TEST_CASE("seed_from_run_id and seed_hex give the pinned values", "[sample-rng]")
{
    const auto [run_id, hex] = GENERATE(table<std::string, std::string>({
        {"run-0001", "8b26e36a"},
        {"a", "0f84a51e"},
        {"live-dry-run", "49b39f4c"},
        {"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", "66f99407"},
    }));
    CAPTURE(run_id);
    CHECK(rp::sampling::seed_hex(rp::sampling::seed_from_run_id(run_id)) == hex);
    CHECK(rp::sampling::seed_from_run_id("run-0001") == 0x8b26e36au);
}

TEST_CASE("seed_hex is 8 lower-case hex digits", "[sample-rng]")
{
    const auto [seed, hex] = GENERATE(table<std::uint32_t, std::string>({
        {0u, "00000000"},
        {0x0000abcdu, "0000abcd"},
        {0x8b26e36au, "8b26e36a"},
        {0xffffffffu, "ffffffff"},
    }));
    CHECK(rp::sampling::seed_hex(seed) == hex);
}

TEST_CASE("stream_seed gives each type and stream its own pinned seed", "[sample-rng]")
{
    const auto [kind, stream, expected] = GENERATE(table<ItemKind, Stream, std::uint32_t>({
        {ItemKind::mail, Stream::browse, 0x7a1ebd96u},
        {ItemKind::mail, Stream::items, 0x63acfd62u},
        {ItemKind::sharepoint, Stream::browse, 0xc8d8e0ddu},
        {ItemKind::sharepoint, Stream::items, 0x4bd76ac2u},
        {ItemKind::onedrive, Stream::browse, 0x3c3e3192u},
        {ItemKind::onedrive, Stream::items, 0x2f1bc0e9u},
    }));
    CAPTURE(rp::connector::to_string(kind));
    CHECK(rp::sampling::stream_seed(0x8b26e36au, kind, stream) == expected);
}

TEST_CASE("SampleRng's outputs and draws are the pinned ones", "[sample-rng]")
{
    SampleRng rng(0x63acfd62);
    CHECK(rng.next() == 4273894158u);
    CHECK(rng.next() == 762822402u);
    CHECK(rng.next() == 2439727279u);

    SampleRng draws(0x63acfd62);
    std::vector<std::uint32_t> got;
    for (int i = 0; i < 5; ++i) {
        got.push_back(draws.below(7));
    }
    CHECK(got == std::vector<std::uint32_t>{2, 6, 3, 3, 6});
}

TEST_CASE("Shuffle is the pinned lazy Fisher-Yates", "[sample-rng]")
{
    SampleRng rng(0x63acfd62);
    Shuffle shuffle(rng, 10);
    CHECK(drain(shuffle) == std::vector<std::size_t>{8, 7, 9, 6, 3, 1, 5, 0, 4, 2});
    // Spent: it stays spent.
    CHECK_FALSE(shuffle.next().has_value());
}

TEST_CASE("Shuffle of 0 yields nothing and draws nothing; of 1 yields 0", "[sample-rng]")
{
    SampleRng rng(0x63acfd62);
    Shuffle none(rng, 0);
    CHECK_FALSE(none.next().has_value());
    CHECK(rng.next() == 4273894158u); // nothing was drawn

    SampleRng one_rng(0x63acfd62);
    Shuffle one(one_rng, 1);
    CHECK(drain(one) == std::vector<std::size_t>{0});
}

TEST_CASE("Shuffle yields each index once, lazily", "[sample-rng]")
{
    SampleRng rng(0x2f1bc0e9);
    Shuffle shuffle(rng, 50);
    std::vector<std::size_t> got = drain(shuffle);
    REQUIRE(got.size() == 50);
    std::ranges::sort(got);
    for (std::size_t i = 0; i < got.size(); ++i) {
        CHECK(got[i] == i);
    }

    // Lazy: taking 3 of 10 draws 3 times, then the engine goes on where it was.
    SampleRng lazy(0x63acfd62);
    Shuffle partial(lazy, 10);
    CHECK(partial.next() == std::optional<std::size_t>{8});
    CHECK(partial.next() == std::optional<std::size_t>{7});
    CHECK(partial.next() == std::optional<std::size_t>{9});
    SampleRng reference(0x63acfd62);
    for (int i = 0; i < 3; ++i) {
        reference.next();
    }
    CHECK(lazy.next() == reference.next());
}
