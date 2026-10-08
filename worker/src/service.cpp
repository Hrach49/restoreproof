#include <rp/service.hpp>

namespace rp {

namespace {

// Point 4: restart after one minute, three times, then nothing; the count is
// reset after a day without a failure.
constexpr unsigned long kRestartDelayMs = 60'000;
constexpr int kRestarts = 3;
constexpr unsigned long kResetPeriodSeconds = 86'400;

} // namespace

ServiceSetup service_setup(std::string_view name, std::string_view command_line)
{
    ServiceSetup setup;
    setup.name = std::string{name};
    setup.display_name = setup.name + " Worker";
    setup.description = std::string{kServiceDescription};
    setup.account = "NT SERVICE\\" + setup.name;
    setup.start_type = ServiceStartType::automatic;
    setup.command_line = std::string{command_line};
    setup.failure_actions.assign(kRestarts,
                                 ServiceAction{ServiceActionKind::restart, kRestartDelayMs});
    // The fourth entry is what makes "three times" true: with three, Windows
    // would repeat the last one and restart for ever.
    setup.failure_actions.push_back(ServiceAction{ServiceActionKind::none, 0});
    setup.reset_period_s = kResetPeriodSeconds;
    return setup;
}

} // namespace rp
