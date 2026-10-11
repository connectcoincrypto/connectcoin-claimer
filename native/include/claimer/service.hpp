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
};
std::optional<UniValue> ReadFrame(std::istream& input, size_t maximum = 16384);
void ExactKeys(const UniValue&, std::initializer_list<std::string_view>);
uint64_t ProtocolInteger(const UniValue&, uint64_t minimum, uint64_t maximum);
std::string PublicDomain(const UniValue&);
Context ParseContext(const UniValue&);
UniValue PublicContext(const Context&);
UniValue ReadyFrame();
bool ConnectionBudgetExhausted(std::string_view target, uint64_t successes);
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
