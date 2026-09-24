#pragma once

// A throwaway HTTP server on 127.0.0.1 for the HTTP client tests, and a port
// nothing listens on. Test-only: cpp-httplib is linked into rptests alone.
//
// httplib.h must come before anything that includes <windows.h>: it needs
// <winsock2.h> first.
#include <httplib.h>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
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

// A TCP listener on 127.0.0.1 that reads what each client sends first (for a
// TLS client, the ClientHello) and then closes the connection: a server that
// drops every connection mid-handshake.
class DroppingServer {
public:
    DroppingServer()
    {
        REQUIRE(WSAStartup(MAKEWORD(2, 2), &wsa_) == 0);
        listener_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        REQUIRE(listener_ != INVALID_SOCKET);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        REQUIRE(::bind(listener_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
        REQUIRE(::listen(listener_, SOMAXCONN) == 0);
        int length = sizeof(addr);
        REQUIRE(::getsockname(listener_, reinterpret_cast<sockaddr*>(&addr), &length) == 0);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] {
            // Ends when the destructor closes the listener and accept() fails.
            for (;;) {
                const SOCKET client = ::accept(listener_, nullptr, nullptr);
                if (client == INVALID_SOCKET) {
                    return;
                }
                char buffer[4096];
                ::recv(client, buffer, sizeof(buffer), 0);
                // Counted before the close, which the client sees.
                ++accepted_;
                ::closesocket(client);
            }
        });
    }

    ~DroppingServer()
    {
        ::closesocket(listener_);
        thread_.join();
        WSACleanup();
    }

    DroppingServer(const DroppingServer&) = delete;
    DroppingServer& operator=(const DroppingServer&) = delete;

    int port() const { return port_; }
    // Connections accepted and dropped so far.
    int accepted() const { return accepted_; }

private:
    WSADATA wsa_{};
    SOCKET listener_ = INVALID_SOCKET;
    int port_ = 0;
    std::atomic<int> accepted_ = 0;
    std::thread thread_;
};

} // namespace rp::test
