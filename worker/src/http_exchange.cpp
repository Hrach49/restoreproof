#include "http_exchange.hpp"

namespace rp {

namespace {

bool is_status(int status) noexcept
{
    return status >= 100 && status <= 999;
}

Exchange failed(std::string_view word)
{
    return {std::nullopt, std::string{word}};
}

} // namespace

Exchange exchange(IHttpClient& http, const HttpRequest& request)
{
    try {
        HttpResponse response = http.send(request);
        if (!is_status(response.status)) {
            return failed(exchange_word::kInternal);
        }
        return {std::move(response), {}};
    } catch (const HttpError& e) {
        if (e.error() == TransportError::none && is_status(e.status())) {
            HttpResponse response;
            response.status = e.status();
            return {std::move(response), {}};
        }
        switch (e.error()) {
        case TransportError::timeout:
            return failed(exchange_word::kTimeout);
        case TransportError::connect:
        case TransportError::dropped:
        case TransportError::handshake:
        case TransportError::tls:
            return failed(exchange_word::kUnreachable);
        default:
            return failed(exchange_word::kInternal);
        }
    } catch (...) {
        return failed(exchange_word::kInternal);
    }
}

} // namespace rp
