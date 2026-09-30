#pragma once

// The errors of the Graph sign-in and Graph calls (W2.1). They live in
// rp::graph because rp::AuthError and its siblings are Veeam's. Every one of
// them means the run could not test anything: its status is `error`, never
// `fail` (docs/verification.md).

#include <rp/config.hpp>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace rp::graph {

// Any failure of the Graph sign-in or a Graph call. what() is safe to print
// and log: it went through rp::redact(), is one line, and never holds a
// token, the client assertion, the PFX or its password. An error keeps what
// was parsed from Graph's or Entra's answer (the status, the code, the inner
// code and the request ID), never the response body.
class GraphError : public std::runtime_error {
public:
    explicit GraphError(std::string_view message, int status = 0, std::string code = {},
                        std::string inner_code = {}, std::string request_id = {});

    // The HTTP status of the answer; 0 when none came back, or when the error
    // isn't about an answer at all.
    int status() const noexcept;
    // Graph's error.code ("ErrorAccessDenied", "accessDenied", ...), or
    // Entra's AADSTS number ("700027") or its "error" when it gave no number;
    // empty when the answer had none.
    const std::string& code() const noexcept;
    // Graph's innerError.code, when the answer had one.
    const std::string& inner_code() const noexcept;
    // The request ID Microsoft can look the call up by: innerError's
    // request-id, else the request-id, client-request-id or x-ms-request-id
    // header. Empty when there was none.
    const std::string& request_id() const noexcept;

private:
    int status_;
    std::string code_;
    std::string inner_code_;
    std::string request_id_;
};

// Entra refused the sign-in (the app, the tenant, the certificate, the clock,
// a policy), or Graph refused the token itself.
class AuthError : public GraphError {
public:
    using GraphError::GraphError;
};

// Graph denied a call for want of a permission. grant() is the grant the call
// relies on, in words a customer can act on (docs/security/graph-permissions.md).
class PermissionError : public GraphError {
public:
    PermissionError(std::string_view message, std::string grant, int status = 0,
                    std::string code = {}, std::string inner_code = {},
                    std::string request_id = {});

    const std::string& grant() const noexcept;

private:
    std::string grant_;
};

// What GraphClient::get() addresses doesn't exist: the mailbox, site, drive
// or item it must find there (a 404 Graph explains). Like every GraphError, the
// run can't test: an item a restore should have put there is looked up with
// GraphClient::find(), which answers its absence with nullopt instead.
class NotFoundError : public GraphError {
public:
    using GraphError::GraphError;
};

// Might work later: no connection, a timeout, a 5xx, a 429, or an Entra code
// that says to try again. retry_after() is what the server asked for, when it
// asked (Retry-After on a 429 or 503).
class TransientError : public GraphError {
public:
    explicit TransientError(std::string_view message, int status = 0, std::string code = {},
                            std::string inner_code = {}, std::string request_id = {},
                            std::optional<std::chrono::seconds> retry_after = std::nullopt);

    const std::optional<std::chrono::seconds>& retry_after() const noexcept;

private:
    std::optional<std::chrono::seconds> retry_after_;
};

// The Worker's client certificate can't be used: its secret variable is unset
// or doesn't hold a PFX the Worker can open, or the certificate in it isn't
// one Entra would accept. Found by load_client_certificate, before any network
// call. A configuration error, not a GraphError: a command catching
// ConfigError reports it as one (exit 1), and a `catch (const GraphError&)`
// doesn't take it for a failed call. what() names the variable, never its
// value, and went through rp::redact(). key() is the variable that is unset
// ("RP_GRAPH_CERT_PFX_BASE64 is not set", "RP_GRAPH_CERT_PASSWORD is not set,
// and ..."), empty for every other reason.
class CertificateError : public ConfigError {
public:
    explicit CertificateError(std::string_view message, std::string key = {});
};

} // namespace rp::graph
