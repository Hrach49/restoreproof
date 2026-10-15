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

// W5.1: a listener on 127.0.0.1 that takes one HTTP/1.1 request as its bytes
// arrive (a request line, headers, then a body of its Content-Length; an
// `Expect: 100-continue` answered first), keeps them, and answers `reply` (a
// whole HTTP response). cpp-httplib parses a multipart body and never hands it
// over raw; this is what holds the Worker's upload byte for byte. No Catch2
// assertion runs on its thread.
class RecordingServer {
public:
    explicit RecordingServer(std::string reply) : reply_(std::move(reply))
    {
        REQUIRE(WSAStartup(MAKEWORD(2, 2), &wsa_) == 0);
        listener_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        REQUIRE(listener_ != INVALID_SOCKET);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        REQUIRE(::bind(listener_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
        REQUIRE(::listen(listener_, 1) == 0);
        int length = sizeof(addr);
        REQUIRE(::getsockname(listener_, reinterpret_cast<sockaddr*>(&addr), &length) == 0);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { serve(); });
    }

    ~RecordingServer()
    {
        ::closesocket(listener_);
        wait();
        WSACleanup();
    }

    // Until the one request is answered and its connection closed.
    void wait()
    {
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    RecordingServer(const RecordingServer&) = delete;
    RecordingServer& operator=(const RecordingServer&) = delete;

    std::string url() const { return "http://127.0.0.1:" + std::to_string(port_); }
    // After wait().
    const std::string& head() const { return head_; }
    const std::string& body() const { return body_; }

private:
    void serve()
    {
        const SOCKET client = ::accept(listener_, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            return;
        }
        std::string got;
        char buffer[8192];
        std::size_t end = std::string::npos;
        while ((end = got.find("\r\n\r\n")) == std::string::npos) {
            const int n = ::recv(client, buffer, sizeof(buffer), 0);
            if (n <= 0) {
                ::closesocket(client);
                return;
            }
            got.append(buffer, static_cast<std::size_t>(n));
        }
        head_ = got.substr(0, end + 4);
        std::string lower = head_;
        for (char& c : lower) {
            c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        }
        if (lower.find("\r\nexpect: 100-continue") != std::string::npos) {
            const std::string go = "HTTP/1.1 100 Continue\r\n\r\n";
            ::send(client, go.data(), static_cast<int>(go.size()), 0);
        }
        std::size_t want = 0;
        if (const std::size_t at = lower.find("\r\ncontent-length:"); at != std::string::npos) {
            want = std::stoull(head_.substr(at + 17));
        }
        body_ = got.substr(end + 4);
        while (body_.size() < want) {
            const int n = ::recv(client, buffer, sizeof(buffer), 0);
            if (n <= 0) {
                break;
            }
            body_.append(buffer, static_cast<std::size_t>(n));
        }
        ::send(client, reply_.data(), static_cast<int>(reply_.size()), 0);
        ::shutdown(client, SD_SEND);
        while (::recv(client, buffer, sizeof(buffer), 0) > 0) {
        }
        ::closesocket(client);
    }

    std::string reply_;
    WSADATA wsa_{};
    SOCKET listener_ = INVALID_SOCKET;
    int port_ = 0;
    std::string head_;
    std::string body_;
    std::thread thread_;
};

} // namespace rp::test
