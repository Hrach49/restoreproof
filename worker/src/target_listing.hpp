#pragma once

// The listing `rpworker graph list` and `rpworker client check` share (W4.10,
// docs/decisions.md 2026-10-09 point 6): one profile's three restore targets
// read through the Worker's app and printed as three tables; `graph list`
// gives it the config's local profile, `client check` a file's.

#include <rp/client_assertion.hpp>
#include <rp/client_profile.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_command.hpp>
#include <rp/recording_http_client.hpp>

#include <iosfwd>
#include <memory>
#include <string>

namespace rp {

// Lists `profile`'s three restore targets with env.make_graph_http (recorded
// under "graph" when `recorder` is set) and, with `hash`, downloads each file
// through env.make_download_http (recorded as size and SHA-256), each file
// target's guard and the mailbox's check first, and prints `heading` then
// the three tables and the summary line to `out`, only once everything is
// read. `certificate` is the Worker app's, opened already; `client_options`
// the Graph client's, its logger set. Returns graph list's exit code with
// its line on `err`: 0; 2 for an AuthError or a PermissionError (the grant
// named); 3 transient; 4 any other GraphError; 1, "error: unexpected
// failure", for anything else (a failed write of `out` included). Never
// throws.
int list_restore_targets(const ClientProfile& profile, bool hash, const std::string& heading,
                         graph::ClientCertificate certificate,
                         const graph::GraphClientOptions& client_options,
                         const GraphCommandEnv& env,
                         const std::shared_ptr<FixtureRecorder>& recorder, std::ostream& out,
                         std::ostream& err);

} // namespace rp
