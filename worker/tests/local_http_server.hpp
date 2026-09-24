#pragma once

// A throwaway HTTP server on 127.0.0.1 for the HTTP client tests, and a port
// nothing listens on. Test-only: cpp-httplib is linked into rptests alone.
//
// httplib.h must come before anything that includes <windows.h>: it needs
// <winsock2.h> first.
#include <httplib.h>

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>
#include <thread>
#include <utility>

namespace rp::test {

// Runs `server` (routes already set, or set before the first request) on an
// ephemeral port of 127.0.0.1 until the object goes away.
template <typename Server = httplib::Server>
class BasicLocalServer {
public:
    explicit BasicLocalServer(std::unique_ptr<Server> server = std::make_unique<Server>())
        : server_(std::move(server))
    {
        port_ = server_->bind_to_any_port("127.0.0.1");
        REQUIRE(port_ > 0);
        thread_ = std::thread([this] { server_->listen_after_bind(); });
        server_->wait_until_ready();
    }

    ~BasicLocalServer()
    {
        server_->stop();
        thread_.join();
    }

    BasicLocalServer(const BasicLocalServer&) = delete;
    BasicLocalServer& operator=(const BasicLocalServer&) = delete;

    Server& server() { return *server_; }
    int port() const { return port_; }
    // "http://127.0.0.1:<port>", no trailing slash.
    std::string url(const std::string& path = "") const
    {
        return scheme() + "://127.0.0.1:" + std::to_string(port_) + path;
    }

private:
    std::string scheme() const
    {
        return std::is_same_v<Server, httplib::Server> ? "http" : "https";
    }

    std::unique_ptr<Server> server_;
    int port_ = 0;
    std::thread thread_;
};

using LocalHttpServer = BasicLocalServer<httplib::Server>;

// A port on 127.0.0.1 that was free a moment ago and that nothing listens on:
// bound to learn a free number, then closed, so a connect is refused.
inline int closed_local_port()
{
    WSADATA wsa{};
    REQUIRE(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    const SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(sock != INVALID_SOCKET);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    REQUIRE(::bind(sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
    int length = sizeof(addr);
    REQUIRE(::getsockname(sock, reinterpret_cast<sockaddr*>(&addr), &length) == 0);
    ::closesocket(sock);
    WSACleanup();
    return ntohs(addr.sin_port);
}

} // namespace rp::test
