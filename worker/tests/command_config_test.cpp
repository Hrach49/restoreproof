// The options the commands share a parser for (src/command_config.hpp):
// `config check`, `veeam list`, `graph list` and `restore`. Each command's own
// tests run its command lines end to end.

#include "../src/command_config.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <optional>
#include <string_view>
#include <vector>

namespace {

using Args = std::vector<std::string_view>;

std::optional<rp::CommandOptions> parse(const Args& args)
{
    return rp::parse_options(args, {"--config", "--record"}, {"--hash"});
}

} // namespace

TEST_CASE("options come in any order, each at most once, a value after each value option",
          "[command_config]")
{
    const std::optional<rp::CommandOptions> none = parse({});
    REQUIRE(none);
    CHECK_FALSE(none->value("--config"));
    CHECK_FALSE(none->has_flag("--hash"));

    const std::optional<rp::CommandOptions> all =
        parse({"--record", "r", "--hash", "--config", "c"});
    REQUIRE(all);
    CHECK(all->value("--config") == "c");
    CHECK(all->value("--record") == "r");
    CHECK(all->has_flag("--hash"));
    CHECK_FALSE(all->value("--hash"));

    // A value is whatever word comes next, even one that looks like an option.
    const std::optional<rp::CommandOptions> odd = parse({"--record", "--config"});
    REQUIRE(odd);
    CHECK(odd->value("--record") == "--config");
    CHECK_FALSE(odd->value("--config"));
}

TEST_CASE("anything else is no command line the parser takes", "[command_config]")
{
    const Args args = GENERATE(values<Args>({
        {"--config"},
        {"--config", "a", "--config", "b"},
        {"--hash", "--hash"},
        {"--hash", "x"},
        {"--other", "x"},
        {"list"},
        {"--record", "a", "--config"},
        {"--Config", "a"},
    }));
    CHECK_FALSE(parse(args));
}

TEST_CASE("without flags a flag's name is an unknown option", "[command_config]")
{
    CHECK_FALSE(rp::parse_options(Args{"--hash"}, {"--config"}));
    CHECK(rp::parse_options(Args{"--config", "c"}, {"--config"})->value("--config") == "c");
}
