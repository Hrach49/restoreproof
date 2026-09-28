#include <rp/config.hpp>
#include <rp/graph_errors.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <type_traits>

using rp::graph::AuthError;
using rp::graph::CertificateError;
using rp::graph::GraphError;
using rp::graph::NotFoundError;
using rp::graph::PermissionError;
using rp::graph::TransientError;

namespace {

// A token-shaped string: what() must never carry one.
constexpr const char* kToken = "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl";

} // namespace

TEST_CASE("GraphError's message goes through redact()", "[graph][errors]")
{
    const GraphError error(std::string("Graph said: Bearer ") + kToken + " client_assertion=" +
                           kToken);
    const std::string what = error.what();
    CHECK(what.find(kToken) == std::string::npos);
    CHECK(what.find("eyJ") == std::string::npos);
    CHECK(what.find("Graph said:") == 0);
}

TEST_CASE("Each Graph error's subclass redacts too", "[graph][errors]")
{
    const std::string message = std::string("token ") + kToken;
    CHECK(std::string(AuthError(message).what()).find(kToken) == std::string::npos);
    CHECK(std::string(PermissionError(message, "grant").what()).find(kToken) ==
          std::string::npos);
    CHECK(std::string(NotFoundError(message).what()).find(kToken) == std::string::npos);
    CHECK(std::string(TransientError(message).what()).find(kToken) == std::string::npos);
    CHECK(std::string(CertificateError(message).what()).find(kToken) == std::string::npos);
}

TEST_CASE("GraphError keeps the parsed status, codes and request ID", "[graph][errors]")
{
    SECTION("all of them")
    {
        const GraphError error("denied", 403, "ErrorAccessDenied", "inner", "req-1");
        CHECK(std::string(error.what()) == "denied");
        CHECK(error.status() == 403);
        CHECK(error.code() == "ErrorAccessDenied");
        CHECK(error.inner_code() == "inner");
        CHECK(error.request_id() == "req-1");
    }
    SECTION("none of them")
    {
        const GraphError error("no answer");
        CHECK(error.status() == 0);
        CHECK(error.code().empty());
        CHECK(error.inner_code().empty());
        CHECK(error.request_id().empty());
    }
}

TEST_CASE("PermissionError names the grant the call relies on", "[graph][errors]")
{
    const PermissionError error("denied", "Sites.Selected read on the test site", 403,
                                "accessDenied", "", "req-2");
    const GraphError& base = error;
    CHECK(error.grant() == "Sites.Selected read on the test site");
    CHECK(base.status() == 403);
    CHECK(base.code() == "accessDenied");
    CHECK(base.request_id() == "req-2");
}

TEST_CASE("TransientError carries Retry-After when there was one", "[graph][errors]")
{
    CHECK_FALSE(TransientError("busy", 503).retry_after().has_value());
    const TransientError error("throttled", 429, "TooManyRequests", "", "req-3",
                               std::chrono::seconds(60));
    REQUIRE(error.retry_after().has_value());
    CHECK(*error.retry_after() == std::chrono::seconds(60));
    CHECK(error.status() == 429);
    CHECK(error.code() == "TooManyRequests");
}

TEST_CASE("CertificateError keeps its message and names no key", "[graph][errors]")
{
    const CertificateError error("RP_GRAPH_CERT_PFX_BASE64 is not set");
    CHECK(std::string(error.what()) == "RP_GRAPH_CERT_PFX_BASE64 is not set");
    CHECK(error.key().empty());
}

// Review of W2.1: CertificateError derived from GraphError, so a natural
// `catch (const GraphError&)` (a command's "other Graph error") would map an
// unset certificate variable to that rather than to a configuration error.
// It is a ConfigError now: exit 1 wherever configuration errors are caught.
TEST_CASE("CertificateError is a configuration error, not a GraphError", "[graph][errors]")
{
    CHECK(std::is_base_of_v<rp::ConfigError, CertificateError>);
    CHECK_FALSE(std::is_base_of_v<GraphError, CertificateError>);

    const auto kind = [](const std::exception_ptr& thrown) -> std::string {
        try {
            std::rethrow_exception(thrown);
        } catch (const GraphError&) {
            return "GraphError";
        } catch (const rp::ConfigError&) {
            return "ConfigError";
        } catch (...) {
            return "other";
        }
    };
    CHECK(kind(std::make_exception_ptr(CertificateError("RP_GRAPH_CERT_PFX_BASE64 is not set"))) ==
          "ConfigError");
    const CertificateError error(std::string("pfx=") + kToken);
    CHECK(std::string(error.what()).find(kToken) == std::string::npos);
}
