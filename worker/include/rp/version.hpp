#pragma once

#include <string_view>

namespace rp {

// Worker version, "major.minor.patch", taken from project(VERSION) in
// worker/CMakeLists.txt. Goes into result bundles and `rpworker --version`.
std::string_view version() noexcept;

} // namespace rp
