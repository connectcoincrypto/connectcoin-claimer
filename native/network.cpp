// Copyright (c) 2026 The ConnectCoin developers. MIT license.
// TLS transcript capture adapted from ConnectCoin Core wallet/p2c_tls.cpp.
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <claimer/network.hpp>
#include "p2c_tls_private.h"
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <set>
#include <utility>

static_assert(MBEDTLS_VERSION_NUMBER == 0x03060700, "Review pinned TLS capture on upgrades");
namespace claimer {
namespace {
using Clock = std::chrono::steady_clock;
constexpr size_t MAX_WIRE_BYTES{65536};
constexpr size_t MAX_PROOF_BYTES{65536};
#ifdef _WIN32
using Socket = SOCKET;
constexpr Socket INVALID_FD{INVALID_SOCKET};
int SocketError() { return WSAGetLastError(); }
bool RetryError(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEALREADY || e == WSAEINTR; }
void CloseSocket(Socket s) { closesocket(s); }
void ShutdownSocket(Socket s) { shutdown(s, SD_BOTH); }
void InitializeSockets()
{
    static const bool initialized = [] {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) throw std::runtime_error("Socket initialization failed");
        return true;
    }();
    (void)initialized; // Winsock remains alive until all capture threads exit.
}
void NonBlocking(Socket s)
{
    u_long mode{1};
    if (ioctlsocket(s, FIONBIO, &mode) != 0) throw std::runtime_error("Cannot configure nonblocking socket");
}
#else
using Socket = int;
constexpr Socket INVALID_FD{-1};
int SocketError() { return errno; }
bool RetryError(int e) { return e == EAGAIN || e == EWOULDBLOCK || e == EINPROGRESS || e == EALREADY || e == EINTR; }
void CloseSocket(Socket s) { close(s); }
void ShutdownSocket(Socket s) { shutdown(s, SHUT_RDWR); }
void InitializeSockets() {}
void NonBlocking(Socket s)
{
    const int flags = fcntl(s, F_GETFL, 0);
    const int fdflags = fcntl(s, F_GETFD, 0);
    if (flags < 0 || fdflags < 0 || fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0 ||
        fcntl(s, F_SETFD, fdflags | FD_CLOEXEC) < 0) throw std::runtime_error("Cannot configure nonblocking socket");
#ifdef SO_NOSIGPIPE
    int enabled{1};
    if (setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) throw std::runtime_error("Cannot configure safe socket writes");
#endif
}
#endif

void Check(const CaptureControl& control, Clock::time_point deadline)
{
    if (control.Cancelled()) throw CaptureCancelled();
    if (Clock::now() >= deadline) throw CaptureTimeout();
}

void Wait(Socket fd, bool read, const CaptureControl& control, Clock::time_point deadline)
{
    for (;;) {
        Check(control, deadline);
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
        const int timeout = static_cast<int>(std::clamp<int64_t>(remaining.count(), 1, 100));
#ifdef _WIN32
        WSAPOLLFD descriptor{fd, static_cast<SHORT>(read ? POLLRDNORM : POLLWRNORM), 0};
        const int ready = WSAPoll(&descriptor, 1, timeout);
#else
        pollfd descriptor{fd, static_cast<short>(read ? POLLIN : POLLOUT), 0};
        const int ready = poll(&descriptor, 1, timeout);
#endif
        Check(control, deadline);
        if (ready > 0) {
            if (descriptor.revents & POLLNVAL) throw std::runtime_error("Invalid capture socket");
            return; // HUP/ERR are resolved by recv/send or SO_ERROR below.
        }
        if (ready < 0 && !RetryError(SocketError())) throw std::runtime_error("Socket poll failed");
    }
}

bool Prefix(const unsigned char* address, const unsigned char* prefix, unsigned bits)
{
    const unsigned bytes = bits / 8, tail = bits % 8;
    return std::equal(address, address + bytes, prefix) &&
           (!tail || (address[bytes] & (0xff << (8 - tail))) == (prefix[bytes] & (0xff << (8 - tail))));
}

bool PublicV4(const unsigned char* a)
{
    // ipaddress.is_global, excluding private/reserved/multicast and shared CGNAT.
    const uint32_t ip = (uint32_t(a[0]) << 24) | (uint32_t(a[1]) << 16) | (uint32_t(a[2]) << 8) | a[3];
    const auto in = [ip](uint32_t prefix, unsigned bits) { return (ip >> (32 - bits)) == (prefix >> (32 - bits)); };
    if (ip == 0xc0000009 || ip == 0xc000000a) return true; // Public protocol anycast exceptions.
    return !(in(0x00000000, 8) || in(0x0a000000, 8) || in(0x64400000, 10) ||
             in(0x7f000000, 8) || in(0xa9fe0000, 16) || in(0xac100000, 12) ||
             in(0xc0000000, 24) || in(0xc0000200, 24) || in(0xc0a80000, 16) ||
             in(0xc6120000, 15) || in(0xc6336400, 24) || in(0xcb007100, 24) ||
             in(0xe0000000, 4) || in(0xf0000000, 4));
}

bool PublicV6(const unsigned char* a)
{
    // Python also rejects IPv4-mapped addresses as reserved before the mapped
    // recursion in its endpoint policy. Only global unicast 2000::/3 survives.
    if ((a[0] & 0xe0) != 0x20) return false;
    const auto in = [a](std::array<unsigned char, 16> prefix, unsigned bits) { return Prefix(a, prefix.data(), bits); };
    if (in({0x20, 0x02}, 16) || in({0x20, 0x01, 0x0d, 0xb8}, 32) || in({0x3f, 0xff}, 20)) return false;
    if (in({0x20, 0x01}, 23)) {
        // Public exceptions in Python's current IANA special-purpose table.
        if (in({0x20, 0x01, 0x00, 0x03}, 32) || in({0x20, 0x01, 0x00, 0x04, 0x01, 0x12}, 48) ||
            in({0x20, 0x01, 0x00, 0x20}, 28) || in({0x20, 0x01, 0x00, 0x30}, 28)) return true;
        const std::array<unsigned char, 16> pcp{0x20, 0x01, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        auto turn = pcp; turn[15] = 2;
        return std::equal(a, a + 16, pcp.begin()) || std::equal(a, a + 16, turn.begin());
    }
    return true;
}

struct Address {
    sockaddr_storage value{};
    int size{};
};
Address SocketAddress(const Endpoint& endpoint, bool loopback_fixture = false)
{
#ifdef CLAIMER_NETWORK_TESTING
    if (loopback_fixture) {
        if ((endpoint.ip != "127.0.0.1" && endpoint.ip != "::1") || endpoint.port == 0)
            throw std::runtime_error("TLS fixture must use literal loopback");
    } else
#else
    (void)loopback_fixture;
#endif
    if (endpoint.port != 443 || !IsPublicIp(endpoint.ip)) throw std::runtime_error("TLS endpoint must be public TCP port 443");
    Address result;
    if (endpoint.family == AF_INET) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(endpoint.port);
        if (inet_pton(AF_INET, endpoint.ip.c_str(), &address.sin_addr) != 1) throw std::runtime_error("Invalid IPv4 endpoint");
        std::memcpy(&result.value, &address, sizeof(address));
        result.size = sizeof(address);
    } else if (endpoint.family == AF_INET6) {
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(endpoint.port);
        if (inet_pton(AF_INET6, endpoint.ip.c_str(), &address.sin6_addr) != 1) throw std::runtime_error("Invalid IPv6 endpoint");
        std::memcpy(&result.value, &address, sizeof(address));
        result.size = sizeof(address);
    } else throw std::runtime_error("Unsupported endpoint family");
    return result;
}

std::string TlsError(int result)
{
    char error[192]{};
    mbedtls_strerror(result, error, sizeof(error));
    return std::string("TLS handshake failed: ") + error;
}

struct Connection {
    mbedtls_ssl_context ssl{};
    mbedtls_ssl_config config{};
    const Hash challenge;
    Socket socket;
    const CaptureControl& control;
    Clock::time_point deadline;
    bool random_set{false}, captured_hello{false};
    std::array<unsigned char, 16384 + 5> sent{};
    size_t sent_size{}, sent_total{}, received_total{};
    Connection(Hash value, Socket fd, const CaptureControl& cancellation, Clock::time_point end)
        : challenge(value), socket(fd), control(cancellation), deadline(end)
    {
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&config);
    }
    ~Connection() { mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&config); }
    static int Random(void* context, unsigned char* output, size_t size) noexcept
    {
        auto& self = *static_cast<Connection*>(context);
        try {
            // Never identify the challenge override by RNG call order or size
            // alone: every ephemeral secret must retain independent randomness.
            if (output == connectcoin_p2c_client_random(&self.ssl) && size == 32) {
                std::copy(self.challenge.begin(), self.challenge.end(), output);
                self.random_set = true;
            } else RandomBytes({output, size});
            return 0;
        } catch (...) { return MBEDTLS_ERR_SSL_INTERNAL_ERROR; }
    }
    static int Send(void* context, const unsigned char* data, size_t size) noexcept
    {
        auto& self = *static_cast<Connection*>(context);
        if (self.control.Cancelled() || Clock::now() >= self.deadline || size > MAX_WIRE_BYTES - self.sent_total) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
#ifdef _WIN32
        const auto result = send(self.socket, reinterpret_cast<const char*>(data), static_cast<int>(size), 0);
#else
#ifdef MSG_NOSIGNAL
        constexpr int flags{MSG_NOSIGNAL};
#else
        constexpr int flags{0};
#endif
        const auto result = send(self.socket, data, size, flags);
#endif
        if (result > 0) {
            const auto count = static_cast<size_t>(result);
            self.sent_total += count;
            if (!self.captured_hello) {
                if (count > self.sent.size() - self.sent_size) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
                std::copy_n(data, count, self.sent.data() + self.sent_size);
                self.sent_size += count;
            }
        }
        if (result >= 0) return static_cast<int>(result);
        return RetryError(SocketError()) ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    static int Receive(void* context, unsigned char* data, size_t size) noexcept
    {
        auto& self = *static_cast<Connection*>(context);
        if (self.control.Cancelled() || Clock::now() >= self.deadline || self.received_total == MAX_WIRE_BYTES) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        size = std::min(size, MAX_WIRE_BYTES - self.received_total);
#ifdef _WIN32
        const auto result = recv(self.socket, reinterpret_cast<char*>(data), static_cast<int>(size), 0);
#else
        const auto result = recv(self.socket, data, size, 0);
#endif
        if (result > 0) self.received_total += static_cast<size_t>(result);
        if (result >= 0) return static_cast<int>(result);
        return RetryError(SocketError()) ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
};

void Append(Bytes& proof, const unsigned char* message, size_t length, unsigned expected)
{
    if (!message || length < 4 || length > MAX_PROOF_BYTES - proof.size() || message[0] != expected ||
        (size_t(message[1]) << 16 | size_t(message[2]) << 8 | message[3]) != length - 4) {
        throw std::runtime_error("Invalid or oversized TLS transcript message");
    }
    proof.insert(proof.end(), message, message + length);
}
} // namespace

// The sole descriptor owner. Cancellation only shutdowns: it cannot close a
// descriptor that an I/O callback might still use, nor race descriptor reuse.
class SocketLease {
public:
    SocketLease(CaptureControl& control, int family) : control_(control)
    {
        std::lock_guard lock(control_.mutex_);
        if (control_.Cancelled()) throw CaptureCancelled();
        if (control_.socket_ != -1) throw std::runtime_error("Capture control already owns a socket");
        fd_ = socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (fd_ == INVALID_FD) throw std::runtime_error("Cannot create capture socket");
        try { NonBlocking(fd_); }
        catch (...) { CloseSocket(fd_); fd_ = INVALID_FD; throw; }
        control_.socket_ = static_cast<std::intptr_t>(fd_);
    }
    ~SocketLease()
    {
        std::lock_guard lock(control_.mutex_);
        control_.socket_ = -1;
        CloseSocket(fd_);
    }
    SocketLease(const SocketLease&) = delete;
    SocketLease& operator=(const SocketLease&) = delete;
    Socket Get() const { return fd_; }
    Clock::time_point Connect(const Address& address, const std::function<void()>& started, std::chrono::milliseconds timeout)
    {
        int result;
        Clock::time_point deadline;
        {
            std::lock_guard lock(control_.mutex_);
            if (control_.Cancelled()) throw CaptureCancelled();
            if (started) started();
            if (control_.Cancelled()) throw CaptureCancelled();
            deadline = Clock::now() + timeout;
            result = connect(fd_, reinterpret_cast<const sockaddr*>(&address.value), address.size);
            if (result != 0 && !RetryError(SocketError())) throw std::runtime_error("TCP connection failed");
        }
        if (result != 0) {
            Wait(fd_, false, control_, deadline);
            int error{};
#ifdef _WIN32
            int length = sizeof(error);
            if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) != 0 || error != 0)
#else
            socklen_t length = sizeof(error);
            if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error != 0)
#endif
                throw std::runtime_error("TCP connection failed");
        }
        Check(control_, deadline);
        return deadline;
    }
private:
    CaptureControl& control_;
    Socket fd_{INVALID_FD};
};

void CaptureControl::Cancel() noexcept
{
    cancelled_.store(true, std::memory_order_release);
    std::lock_guard lock(mutex_);
    if (socket_ != -1) ShutdownSocket(static_cast<Socket>(socket_));
}

bool IsPublicIp(std::string_view ip)
{
    InitializeSockets();
    if (ip.empty() || ip.size() >= INET6_ADDRSTRLEN || ip.find('\0') != std::string_view::npos || ip.find('%') != std::string_view::npos) return false;
    const std::string text(ip);
    std::array<unsigned char, 16> address{};
    if (inet_pton(AF_INET, text.c_str(), address.data()) == 1) return PublicV4(address.data());
    if (inet_pton(AF_INET6, text.c_str(), address.data()) == 1) return PublicV6(address.data());
    return false;
}

std::vector<Endpoint> ResolveEndpoints(const std::string& domain, uint16_t port)
{
    if (!IsCanonicalDomain(domain) || port != 443) throw std::runtime_error("Invalid public TLS resolution request");
    InitializeSockets();
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;
    addrinfo* raw{};
    if (getaddrinfo(domain.c_str(), "443", &hints, &raw) != 0) throw std::runtime_error("DNS resolution failed");
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addresses(raw, freeaddrinfo);
    std::vector<Endpoint> result;
    std::set<std::string> seen;
    // Bound processing as well as retained endpoints for unusual resolver data.
    size_t inspected{};
    for (auto* entry = raw; entry && result.size() < 32 && inspected++ < 256; entry = entry->ai_next) {
        char text[INET6_ADDRSTRLEN]{};
        const void* address{};
        if (!entry->ai_addr || entry->ai_socktype != SOCK_STREAM || entry->ai_protocol != IPPROTO_TCP) continue;
        if (entry->ai_family == AF_INET && entry->ai_addrlen >= sizeof(sockaddr_in))
            address = &reinterpret_cast<const sockaddr_in*>(entry->ai_addr)->sin_addr;
        else if (entry->ai_family == AF_INET6 && entry->ai_addrlen >= sizeof(sockaddr_in6)) {
            const auto* v6 = reinterpret_cast<const sockaddr_in6*>(entry->ai_addr);
            if (v6->sin6_scope_id != 0) continue;
            address = &v6->sin6_addr;
        }
        if (!address || !inet_ntop(entry->ai_family, address, text, sizeof(text)) || !IsPublicIp(text)) continue;
        Endpoint endpoint{text, entry->ai_family, port};
        if (seen.insert(endpoint.Key()).second) result.push_back(std::move(endpoint));
    }
    if (result.empty()) throw std::runtime_error("Domain resolved to no permitted TCP addresses");
    return result;
}

static Bytes CaptureImpl(const Context& context, const Endpoint& endpoint, CaptureControl& control,
                         const std::function<void()>& on_started, std::chrono::milliseconds timeout,
                         bool complete_handshake, bool loopback_fixture)
{
    ValidateContext(context);
    if (timeout <= std::chrono::milliseconds::zero()) throw std::runtime_error("Invalid TLS timeout");
    timeout = std::min(timeout, std::chrono::milliseconds{10000});
    if (control.Cancelled()) throw CaptureCancelled();
    InitializeSockets();
    const Address address = SocketAddress(endpoint, loopback_fixture);
    InitializeCrypto();
    const Hash challenge = ClaimChallenge(context);
    SocketLease socket(control, endpoint.family);
    const auto deadline = socket.Connect(address, on_started, timeout);
    Connection connection(challenge, socket.Get(), control, deadline);
    static constexpr int suites[]{MBEDTLS_TLS1_3_AES_128_GCM_SHA256, MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256, 0};
    static constexpr uint16_t groups[]{29, 23, 0};
    std::vector<uint16_t> signatures;
    if (context.signature_algorithms_mask & 1) signatures.push_back(0x0403);
    if (context.signature_algorithms_mask & 2) signatures.push_back(0x0804);
    if (context.signature_algorithms_mask & 4) signatures.push_back(0x0809);
    signatures.push_back(0);
    int result = mbedtls_ssl_config_defaults(&connection.config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (result != 0) throw std::runtime_error(TlsError(result));
    mbedtls_ssl_conf_min_tls_version(&connection.config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&connection.config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_tls13_key_exchange_modes(&connection.config, MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
    mbedtls_ssl_conf_ciphersuites(&connection.config, suites);
    mbedtls_ssl_conf_groups(&connection.config, groups);
    mbedtls_ssl_conf_sig_algs(&connection.config, signatures.data());
    // No OS roots or wall-clock trust. VerifyProof authenticates the captured
    // bytes later using immutable roots and the supplied chain median time.
    mbedtls_ssl_conf_authmode(&connection.config, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&connection.config, Connection::Random, &connection);
    result = mbedtls_ssl_setup(&connection.ssl, &connection.config);
    if (result == 0) result = mbedtls_ssl_set_hostname(&connection.ssl, context.domain.c_str());
    if (result != 0) throw std::runtime_error(TlsError(result));
    mbedtls_ssl_set_bio(&connection.ssl, &connection, Connection::Send, Connection::Receive, nullptr);
    Bytes proof{2};
    unsigned captured{};
    bool captured_verify{false};
    for (;;) {
        Check(control, deadline);
        const int state = connection.ssl.state;
        if (state == MBEDTLS_SSL_CLIENT_HELLO && connection.captured_hello) throw std::runtime_error("TLS HelloRetryRequest is unsupported");
        // Normal capture stops before CV verification, preserving separate
        // capture/validation timing and avoiding duplicate signature work.
        result = state == MBEDTLS_SSL_CERTIFICATE_VERIFY && !complete_handshake
            ? connectcoin_p2c_fetch_certificate_verify(&connection.ssl)
            : mbedtls_ssl_handshake_step(&connection.ssl);
        Check(control, deadline);
        if (!connection.captured_hello && connection.sent_size >= 5) {
            const size_t length = size_t(connection.sent[3]) * 256 + connection.sent[4];
            if (connection.sent[0] != 22 || length < 4 || length > connection.sent.size() - 5) throw std::runtime_error("Invalid outgoing ClientHello record");
            if (connection.sent_size >= length + 5) {
                if (!connection.random_set || connection.sent_size != length + 5) throw std::runtime_error("Unsupported ClientHello randomness or record layout");
                Append(proof, connection.sent.data() + 5, length, 1);
                connection.captured_hello = true;
            }
        }
        if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) {
            Wait(socket.Get(), result == MBEDTLS_ERR_SSL_WANT_READ, control, deadline);
            continue;
        }
        if (result != 0) throw std::runtime_error(TlsError(result));
        unsigned expected{};
        if (state == MBEDTLS_SSL_SERVER_HELLO) expected = 2;
        else if (state == MBEDTLS_SSL_ENCRYPTED_EXTENSIONS) expected = 8;
        else if (state == MBEDTLS_SSL_SERVER_CERTIFICATE) expected = 11;
        else if (state == MBEDTLS_SSL_CERTIFICATE_VERIFY) expected = 15;
        if (expected) {
            static constexpr unsigned order[]{2, 8, 11, 15};
            if (!connection.captured_hello || captured >= 4 || expected != order[captured++]) throw std::runtime_error("Unexpected TLS transcript order");
            const auto* message = connection.ssl.in_msg;
            const auto length = connection.ssl.in_hslen;
            Append(proof, message, length, expected);
            if (expected == 11) ValidateCertificateMessage({message, length});
            if (expected == 15) {
                // Structural checks and signature-mask enforcement only. Full
                // certificate/CV authentication is the caller's responsibility.
                ParseProof(proof, context);
                captured_verify = true;
                if (!complete_handshake) return proof;
            }
        }
        if (connection.ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
            if (!captured_verify) throw std::runtime_error("TLS handshake ended before CertificateVerify");
            // No application data is ever written. Best-effort close_notify is
            // bounded independently and cannot invalidate a completed capture.
            const auto close_deadline = std::min(deadline, Clock::now() + std::chrono::milliseconds{200});
            do {
                if (control.Cancelled()) throw CaptureCancelled();
                if (Clock::now() >= close_deadline) break;
                result = mbedtls_ssl_close_notify(&connection.ssl);
                if (result != MBEDTLS_ERR_SSL_WANT_WRITE) break;
                try { Wait(socket.Get(), false, control, close_deadline); }
                catch (const CaptureTimeout&) { break; }
            } while (Clock::now() < close_deadline);
            return proof;
        }
    }
}

Bytes Capture(const Context& context, const Endpoint& endpoint, CaptureControl& control,
              const std::function<void()>& on_started, std::chrono::milliseconds timeout, bool complete_handshake)
{
    return CaptureImpl(context, endpoint, control, on_started, timeout, complete_handshake, false);
}
#ifdef CLAIMER_NETWORK_TESTING
Bytes CaptureForTesting(const Context& context, const Endpoint& endpoint, CaptureControl& control,
                        const std::function<void()>& on_started, std::chrono::milliseconds timeout, bool complete_handshake)
{
    return CaptureImpl(context, endpoint, control, on_started, timeout, complete_handshake, true);
}
#endif
} // namespace claimer
