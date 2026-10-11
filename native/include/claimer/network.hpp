// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#pragma once
#include <claimer/crypto.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace claimer {
struct Endpoint {
    std::string ip;
    int family{}; // AF_INET or AF_INET6 on this platform.
    uint16_t port{443};
    bool operator==(const Endpoint&) const = default;
    std::string Key() const { return std::to_string(family) + ":" + ip + ":" + std::to_string(port); }
};
struct CaptureCancelled : std::runtime_error { CaptureCancelled() : std::runtime_error("TLS capture cancelled") {} };
struct CaptureTimeout : std::runtime_error { CaptureTimeout() : std::runtime_error("TLS connection timed out") {} };
class SocketLease;
class CaptureControl {
public:
    CaptureControl() = default;
    CaptureControl(const CaptureControl&) = delete;
    CaptureControl& operator=(const CaptureControl&) = delete;
    void Cancel() noexcept;
    bool Cancelled() const noexcept { return cancelled_.load(std::memory_order_acquire); }
private:
    std::atomic<bool> cancelled_{false};
    std::mutex mutex_;
    std::intptr_t socket_{-1};
    friend class SocketLease;
};
// DNS is deliberately separate: service callers cache resolutions, never resolve
// per capture. No private-address escape hatch exists in the production API.
bool IsPublicIp(std::string_view ip);
std::vector<Endpoint> ResolveEndpoints(const std::string& domain, uint16_t port = 443);
// on_started runs immediately before connect, under this control's socket lock.
// It may throw or poll Cancelled(), but must not invoke Cancel() recursively.
// The network deadline begins after on_started returns. Cancel publishes its
// atomic flag before waiting for the socket lock, so paced starts are cancellable.
// Capture owns its socket until exit; cancellation shuts it down without closing
// or permitting descriptor reuse. Caller must keep control alive until exit.
Bytes Capture(const Context& context, const Endpoint& endpoint, CaptureControl& control,
              const std::function<void()>& on_started = {},
              std::chrono::milliseconds timeout = std::chrono::seconds{10},
              bool complete_handshake = false);
#ifdef CLAIMER_NETWORK_TESTING
// Available only in the separately compiled offline-fixture target, never in
// connectcoin-claims. This entry point only permits literal loopback addresses.
Bytes CaptureForTesting(const Context& context, const Endpoint& endpoint, CaptureControl& control,
                        const std::function<void()>& on_started = {},
                        std::chrono::milliseconds timeout = std::chrono::seconds{10},
                        bool complete_handshake = false);
#endif
} // namespace claimer
