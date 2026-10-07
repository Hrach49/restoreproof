#pragma once

// The vault's test seam (W4.5 code review, PR #162): not part of the public
// surface. Only the tests include it.

#include <functional>

namespace rp::detail {

// Tests only. `hook` is called each time a vault file's owner has passed the
// owner rule, before the file is read, written over or its DACL changed: the
// moment at which another account could move a file of its own onto the path.
// An empty function (the default) turns it off. Not thread-safe: set it and
// take it away around one call.
void set_vault_owner_checked_hook(std::function<void()> hook);

} // namespace rp::detail
