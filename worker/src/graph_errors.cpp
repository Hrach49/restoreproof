#include <rp/graph_errors.hpp>

#include <rp/redact.hpp>

#include <utility>

namespace rp::graph {

GraphError::GraphError(std::string_view message, int status, std::string code,
                       std::string inner_code, std::string request_id)
    : std::runtime_error(redact(message)), status_(status), code_(std::move(code)),
      inner_code_(std::move(inner_code)), request_id_(std::move(request_id))
{
}

int GraphError::status() const noexcept
{
    return status_;
}

const std::string& GraphError::code() const noexcept
{
    return code_;
}

const std::string& GraphError::inner_code() const noexcept
{
    return inner_code_;
}

const std::string& GraphError::request_id() const noexcept
{
    return request_id_;
}

PermissionError::PermissionError(std::string_view message, std::string grant, int status,
                                 std::string code, std::string inner_code, std::string request_id)
    : GraphError(message, status, std::move(code), std::move(inner_code), std::move(request_id)),
      grant_(std::move(grant))
{
}

const std::string& PermissionError::grant() const noexcept
{
    return grant_;
}

TransientError::TransientError(std::string_view message, int status, std::string code,
                               std::string inner_code, std::string request_id,
                               std::optional<std::chrono::seconds> retry_after)
    : GraphError(message, status, std::move(code), std::move(inner_code), std::move(request_id)),
      retry_after_(retry_after)
{
}

const std::optional<std::chrono::seconds>& TransientError::retry_after() const noexcept
{
    return retry_after_;
}

CertificateError::CertificateError(std::string_view message, std::string key)
    : ConfigError(std::move(key), redact(message))
{
}

} // namespace rp::graph
