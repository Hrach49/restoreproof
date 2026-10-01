// rptests' main (Q2.1): Catch2's, with the network guard around it. Unless
// RP_LIVE=1, rp::HttpClient may connect to the loopback range alone
// (src/http_client_detail.hpp, set_loopback_only): the unit suite talks to
// fakes and to servers on 127.0.0.1, never to Veeam, Graph or anything else.
// A test case during which the guard refused a connection is named on stderr,
// and the run fails even if the test itself passed (a test expecting a
// connection error would): its exit code is 1 when Catch2's was 0. ctest runs
// each test case in its own process, so the failing case is the one named.

#include "../src/http_client_detail.hpp"

#include <catch2/catch_session.hpp>
#include <catch2/catch_test_case_info.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

// Test cases during which the guard refused a connection.
std::vector<std::string>& offenders()
{
    static std::vector<std::string> names;
    return names;
}

class NetworkGuardListener final : public Catch::EventListenerBase {
public:
    using Catch::EventListenerBase::EventListenerBase;

    void testCaseStarting(const Catch::TestCaseInfo&) override
    {
        rp::detail::take_refused_connections();
    }

    void testCaseEnded(const Catch::TestCaseStats& stats) override
    {
        const std::uint64_t refused = rp::detail::take_refused_connections();
        if (refused > 0) {
            offenders().push_back(stats.testInfo->name);
            std::cerr << "NETWORK GUARD: \"" << stats.testInfo->name << "\" tried to connect "
                      << refused << " time(s) outside 127.0.0.1\n";
        }
    }
};

} // namespace

CATCH_REGISTER_LISTENER(NetworkGuardListener)

// Whether RP_LIVE=1. Not rp::test::get_env, whose REQUIREs abort outside a
// test case.
bool live_run()
{
    wchar_t* value = nullptr;
    std::size_t length = 0;
    if (_wdupenv_s(&value, &length, L"RP_LIVE") != 0 || value == nullptr) {
        return false;
    }
    const bool live = std::wstring_view{value} == L"1";
    std::free(value);
    return live;
}

int main(int argc, char* argv[])
{
    rp::detail::set_loopback_only(!live_run());
    const int result = Catch::Session().run(argc, argv);
    if (!offenders().empty()) {
        std::cerr << "NETWORK GUARD: " << offenders().size()
                  << " test case(s) tried to connect outside 127.0.0.1\n";
        return result == 0 ? 1 : result;
    }
    return result;
}
