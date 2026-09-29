// W2.7 (#32): the target guard is the first line of VeeamM365Connector::
// restore_sample. Veeam is a FakeHttpClient that serves nothing, so any
// request to it shows in its log; Graph is the guard's lab (target_guard_lab.hpp)
// on the recorded replies for the three restore targets.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "target_guard_lab.hpp"

#include <rp/connector.hpp>
#include <rp/veeam_m365_connector.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <exception>
#include <functional>
#include <memory>
#include <string>

using Catch::Matchers::StartsWith;

namespace {

namespace connector = rp::connector;
using nlohmann::json;
using rp::test::load_fixture_json;
using namespace rp::test::target_guard_lab;

const std::string kBase = "https://veeam.test:4443";

// A connector whose Veeam serves nothing, guarded through `lab`'s Graph.
struct Rig {
    rp::test::FakeHttpClient veeam;
    GuardLab lab;
    std::unique_ptr<rp::VeeamM365Connector> source;

    explicit Rig(bool with_graph = true)
    {
        source = std::make_unique<rp::VeeamM365Connector>(
            std::make_unique<rp::test::ForwardingHttpClient>(veeam), kBase, "rp-veeam",
            "Sentinel-Veeam-Password-2b7e", rp::VeeamClientOptions{},
            with_graph ? lab.graph : nullptr, lab.options());
    }
};

// What restore_sample threw: the connector error's kind and message.
struct Caught {
    std::string kind = "none";
    std::string what;
};

Caught caught_by(const std::function<void()>& call)
{
    try {
        call();
    } catch (const connector::SafetyViolation& e) {
        return {"SafetyViolation", e.what()};
    } catch (const connector::AuthError& e) {
        return {"AuthError", e.what()};
    } catch (const connector::TransientError& e) {
        return {"TransientError", e.what()};
    } catch (const connector::NotFoundError& e) {
        return {"NotFoundError", e.what()};
    } catch (const connector::NotImplementedError& e) {
        return {"NotImplementedError", e.what()};
    } catch (const connector::Error& e) {
        return {"Error", e.what()};
    } catch (const std::exception& e) {
        return {"not a connector error", e.what()};
    }
    return {};
}

} // namespace

TEST_CASE("restore_sample refuses a restore target before any Veeam request", "[veeam_m365][target_guard]")
{
    Rig rig;
    // An item sampled from the test mailbox itself.
    const connector::RestoreSpec spec =
        make_spec({mail_source(), {lab_values().mailbox, "Inbox", "s"}});

    const Caught thrown = caught_by([&] { rig.source->restore_sample(spec); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK_THAT(thrown.what, StartsWith("target guard: mail item 1 is sampled from a restore target"));
    CHECK(rig.veeam.requests().empty());
    CHECK(rig.lab.graph_gets() == 0);
}

TEST_CASE("restore_sample refuses a configured target Graph shows is wrong, before Veeam",
          "[veeam_m365][target_guard]")
{
    Rig rig;
    rig.lab.serve_edited(drive_url(), "restoretarget-drive-200",
                         [](json& b) { b["name"] = "Dokumenty"; });

    const Caught thrown = caught_by([&] { rig.source->restore_sample(full_spec()); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK_THAT(thrown.what, StartsWith("target guard: the drive test_library_id names is"));
    CHECK(rig.veeam.requests().empty());
}

TEST_CASE("restore_sample resolves every target first and still sends Veeam nothing",
          "[veeam_m365][target_guard]")
{
    Rig rig;

    const Caught thrown = caught_by([&] { rig.source->restore_sample(full_spec()); });

    CHECK(thrown.kind == "NotImplementedError");
    CHECK(thrown.what == "veeam_m365: restore_sample is not implemented yet (W2.5)");
    CHECK(rig.lab.gets(inbox_url()) == 1);
    CHECK(rig.lab.gets(drive_url()) == 1);
    CHECK(rig.lab.gets(folder_url()) == 1);
    CHECK(rig.veeam.requests().empty());
    CHECK(rig.lab.log().empty());
}

TEST_CASE("restore_sample without a Graph client refuses to run", "[veeam_m365][target_guard]")
{
    Rig rig(false);

    const Caught thrown = caught_by([&] { rig.source->restore_sample(full_spec()); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what ==
          "veeam_m365: no Graph client, so the target guard can't run; nothing was restored");
    CHECK(rig.veeam.requests().empty());
    CHECK(rig.lab.graph_http.requests().empty());
}

TEST_CASE("restore_sample turns the guard's Graph errors into connector errors",
          "[veeam_m365][target_guard]")
{
    struct Row {
        std::string name;
        std::string url;
        std::string fixture;
        std::string kind;
    };
    const Row row = GENERATE(values<Row>({
        {"a 403 on the library", drive_url(), "site-403-accessdenied", "AuthError"},
        {"a 503 on the Inbox", inbox_url(), "messages-503-unavailable", "TransientError"},
        {"a 404 on the folder", folder_url(), "onedrive-folder-404-itemnotfound", "NotFoundError"},
        {"a 404 on the Inbox", inbox_url(), "messages-404-mailbox-not-enabled", "Error"},
    }));
    CAPTURE(row.name);
    Rig rig;
    rig.lab.serve(row.url, load_fixture_json("graph", row.fixture));

    const Caught thrown = caught_by([&] { rig.source->restore_sample(full_spec()); });

    CHECK(thrown.kind == row.kind);
    CHECK_THAT(thrown.what, !StartsWith("target guard: "));
    CHECK(rig.veeam.requests().empty());
}
