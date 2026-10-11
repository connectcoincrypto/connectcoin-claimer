// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#pragma once
#include <claimer/crypto.hpp>
#include <claimer/network.hpp>
#include <univalue.h>
#include <functional>
#include <istream>
#include <memory>
#include <optional>

namespace claimer {
using Emit = std::function<void(const std::string&)>;
struct ServiceDependencies {
    std::function<std::vector<Endpoint>(const std::string&)> resolve;
    std::function<Bytes(const Context&, const Endpoint&, CaptureControl&, const std::function<void()>&)> capture;
    std::function<Verification(const Bytes&, const Context&)> verify;
    // Monotonic time for temporary local reachability exclusions. Separate from
    // real socket pacing so offline tests can exercise recovery without sleeps.
    std::function<double()> reachability_time;
};
// Retains only a bounded reusable line buffer; getline stops at the delimiter,
// never waits for a full block and never consumes the next protocol frame.
class ProtocolFrameReader {
    std::istream& input_;
    std::vector<char> buffer_;
public:
    explicit ProtocolFrameReader(std::istream& input) : input_(input) {}
    std::optional<UniValue> Next(size_t maximum = 16384);
};
std::optional<UniValue> ReadFrame(std::istream& input, size_t maximum = 16384);
void ExactKeys(const UniValue&, std::initializer_list<std::string_view>);
uint64_t ProtocolInteger(const UniValue&, uint64_t minimum, uint64_t maximum);
std::string PublicDomain(const UniValue&);
Context ParseContext(const UniValue&);
UniValue PublicContext(const Context&);
UniValue ReadyFrame();
bool ConnectionBudgetExhausted(std::string_view target, uint64_t successes);
// First success count that forbids another start. UINT64_MAX remains the
// saturation stop even when the mathematical budget is larger than uint64_t.
uint64_t ConnectionBudgetStopCount(std::string_view target);
double AdvanceConnectionDeadline(double previous, double now, uint32_t rate, bool idle);
class ClaimsService {
public:
    ClaimsService(const UniValue& options, Emit emit, ServiceDependencies dependencies = {});
    ~ClaimsService();
    ClaimsService(const ClaimsService&) = delete;
    ClaimsService& operator=(const ClaimsService&) = delete;
    void Command(const UniValue&);
    void Close();
    bool Failed() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
int RunService(std::istream&, Emit);
} // namespace claimer
