// Offline protocol/lifecycle regression tests. No DNS or sockets are used.
#include <claimer/service.hpp>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

using namespace claimer;
using namespace std::chrono_literals;
namespace {
void Check(bool condition, const char* name) { if (!condition) throw std::runtime_error(name); }
template<class Function> void Rejects(Function function) { bool rejected = false; try { function(); } catch (...) { rejected = true; } Check(rejected, "Input should have been rejected"); }
UniValue Json(const std::string& text) { std::istringstream input(text + "\n"); return *ReadFrame(input); }
Context ContextFor(uint8_t mask = 7) { return {"example.com", std::string(64, 'a'), 0, std::string(64, '0'), 1, mask, 1800000000}; }
UniValue Attempt(uint64_t id, Context context = ContextFor(), std::string count = "0") {
    UniValue value(UniValue::VOBJ); value.pushKV("type", "attempt"); value.pushKV("id", id); value.pushKV("context", PublicContext(context));
    value.pushKV("bountyId", std::string(64, 'a') + ":0"); value.pushKV("successfulConnections", count); return value;
}
UniValue Resolve(uint64_t id, std::string domain = "example.com") { UniValue value(UniValue::VOBJ); value.pushKV("type", "resolve"); value.pushKV("id", id); value.pushKV("domain", domain); return value; }
UniValue Cancel(uint64_t id) { UniValue value(UniValue::VOBJ); value.pushKV("type", "cancel"); value.pushKV("id", id); return value; }
struct Fixture {
    std::mutex mutex;
    std::condition_variable condition;
    std::vector<UniValue> frames;
    std::unique_ptr<ClaimsService> service;
    std::atomic<int> resolutions{}, captures{}, verifications{};
    explicit Fixture(size_t concurrency = 2, ServiceDependencies overrides = {}) {
        ServiceDependencies deps;
        deps.resolve = [this](const std::string&) { ++resolutions; return std::vector<Endpoint>{{"8.8.8.8", 2, 443}, {"1.1.1.1", 2, 443}}; };
        deps.capture = [this](const Context&, const Endpoint&, CaptureControl&, const std::function<void()>& started) { started(); ++captures; return Bytes{2, 1}; };
        deps.verify = [this](const Bytes&, const Context&) { ++verifications; return Verification{std::string(64, '0'), true, 0x0403}; };
        if (overrides.resolve) deps.resolve = overrides.resolve;
        if (overrides.capture) deps.capture = overrides.capture;
        if (overrides.verify) deps.verify = overrides.verify;
        UniValue options(UniValue::VOBJ); options.pushKV("connectionsPerSecond", 100000); options.pushKV("concurrency", static_cast<uint64_t>(concurrency));
        service = std::make_unique<ClaimsService>(options, [this](const std::string& text) { UniValue frame; Check(frame.read(text), "Output is JSON"); { std::lock_guard lock(mutex); frames.push_back(std::move(frame)); } condition.notify_all(); }, deps);
    }
    ~Fixture() { service->Close(); }
    UniValue Wait(const char* type, uint64_t id) {
        std::unique_lock lock(mutex);
        const auto match = [&](const UniValue& frame) { return frame["type"].isStr() && frame["type"].get_str() == type && frame["id"].isNum() && frame["id"].getInt<uint64_t>() == id; };
        Check(condition.wait_for(lock, 3s, [&] { return std::any_of(frames.begin(), frames.end(), match); }), "Timed out waiting for service frame");
        return *std::find_if(frames.begin(), frames.end(), match);
    }
    void Ready() { service->Command(Resolve(1)); Check(Wait("resolved", 1)["ok"].isTrue(), "Fake resolution failed"); }
};
void Parsing() {
    for (const auto& value : {"{\"a\":1,\"a\":2}\n", "{\"x\":{\"a\":1,\"a\":2}}\n", "{\"x\":NaN}\n", "{}", "[1,]\n"}) {
        Rejects([&] { std::istringstream input(value); ReadFrame(input); });
    }
    Rejects([] { std::istringstream input(std::string(16384, ' ') + "\n"); ReadFrame(input); });
    std::istringstream empty; Check(!ReadFrame(empty), "Clean EOF");
    auto context = PublicContext(ContextFor()); Check(ParseContext(context).domain == "example.com", "Public context roundtrip");
    for (const auto& value : {"true", "1.0", "1e0", "-1", "9007199254740992"}) Rejects([&] { ProtocolInteger(Json(value), 1, (uint64_t{1} << 53) - 1); });
    for (const auto& value : {"LOCALHOST", "x.local", "x.internal", "x.localhost", "example.com.", "a..com"}) Rejects([&] { PublicDomain(UniValue(value)); });
}
void BudgetAndPacing() {
    const std::string maximum(64, 'f'), zero(64, '0');
    Check(!ConnectionBudgetExhausted(maximum, 2), "Budget equality must remain eligible");
    Check(ConnectionBudgetExhausted(maximum, 3), "Budget over equality must block");
    Check(!ConnectionBudgetExhausted("7" + std::string(63, 'f'), 4), "257-bit equality");
    Check(ConnectionBudgetExhausted("7" + std::string(63, 'f'), 5), "257-bit overflow");
    Check(ConnectionBudgetExhausted("8" + std::string(63, '0'), 4), "Boundary plus low limb");
    Check(!ConnectionBudgetExhausted(zero, UINT64_MAX - 1), "Hard work never exceeds budget early");
    Check(ConnectionBudgetExhausted(zero, UINT64_MAX), "Saturated counter blocks");
    Check(!ConnectionBudgetExhausted("00003" + std::string(59, 'f'), 524288), "Common target exact equality");
    Check(ConnectionBudgetExhausted("00003" + std::string(59, 'f'), 524289), "Common target above equality");
    Check(std::abs(AdvanceConnectionDeadline(0, 100, 100, true) - 100.01) < 1e-10, "Idle demand cannot earn credit");
    Check(std::abs(AdvanceConnectionDeadline(100, 103, 100, false) - 102) < 1e-10, "Lateness bounded to one second");
    Check(std::abs(AdvanceConnectionDeadline(100, 100, 400, false) - 100.0025) < 1e-10, "Rate is configurable");
}
void SuccessfulAndMissedProof() {
    Fixture fixture; fixture.Ready(); fixture.service->Command(Attempt(2));
    const auto final = fixture.Wait("attempt", 2);
    Check(final["verified"].isTrue() && final["validationPassed"].isTrue() && final["proof"].get_str() == "0201", "Verified proof expected");
    Check(final["successfulConnections"].get_str() == "1", "Raw capture counted exactly once");
    const auto capture = fixture.Wait("capture", 2);
    Check(capture["successfulConnections"].get_str() == final["successfulConnections"].get_str(), "Frozen counter snapshot");
    { std::lock_guard lock(fixture.mutex); std::vector<std::string> order; for (const auto& frame : fixture.frames) if (frame["id"].getInt<uint64_t>() == 2) order.push_back(frame["type"].get_str()); Check(order == std::vector<std::string>{"started", "capture", "attempt"}, "Frame order"); }
    ServiceDependencies deps; deps.verify = [](const Bytes&, const Context&) { return Verification{std::string(64, 'f'), false, 0x0403}; };
    Fixture miss(1, deps); miss.Ready(); miss.service->Command(Attempt(2)); const auto value = miss.Wait("attempt", 2);
    Check(value["validationPassed"].isTrue() && value["proof"].isNull() && value["verified"].isFalse(), "Hash miss still fully validated");
}
void FailuresAndDnsCache() {
    Fixture missing; missing.service->Command(Attempt(1)); const auto frame = missing.Wait("attempt", 1);
    Check(frame["started"].isFalse() && frame["validationPassed"].isNull(), "No attempt before DNS resolution");
    Fixture cache; cache.Ready(); cache.service->Command(Resolve(2)); cache.Wait("resolved", 2); Check(cache.resolutions == 1, "DNS cached");
    ServiceDependencies deps; deps.capture = [](const Context&, const Endpoint&, CaptureControl&, const std::function<void()>& started) -> Bytes { started(); throw CaptureTimeout(); };
    Fixture failed(1, deps); failed.Ready(); failed.service->Command(Attempt(2)); const auto value = failed.Wait("attempt", 2);
    Check(value["started"].isTrue() && value["captured"].isFalse() && value["validationPassed"].isFalse(), "Conclusive capture failure retained");
    Check(value["message"].get_str() == "TLS connection timed out", "Timeout message sanitized");
    Check(value["successfulConnections"].get_str() == "0", "Failed capture is not budgeted");
}
void CancelQueuedAndActive() {
    ServiceDependencies deps; deps.capture = [](const Context&, const Endpoint&, CaptureControl& control, const std::function<void()>& started) -> Bytes { started(); while (!control.Cancelled()) std::this_thread::sleep_for(1ms); throw CaptureCancelled(); };
    Fixture fixture(1, deps); fixture.Ready(); fixture.service->Command(Attempt(2)); fixture.Wait("started", 2);
    fixture.service->Command(Attempt(3)); fixture.service->Command(Cancel(3)); const auto queued = fixture.Wait("attempt", 3);
    Check(queued["cancelled"].isTrue() && queued["started"].isFalse() && queued["validationPassed"].isNull(), "Queued cancellation");
    fixture.service->Command(Resolve(4, "other.example")); Check(fixture.Wait("resolved", 4)["ok"].isTrue(), "DNS slot independent of occupied TLS slot");
    fixture.service->Command(Cancel(2)); const auto active = fixture.Wait("attempt", 2);
    Check(active["cancelled"].isTrue() && active["started"].isTrue() && active["validationPassed"].isNull(), "Inconclusive active cancellation");
    fixture.service->Close(); Rejects([&] { fixture.service->Command(Attempt(5)); });
}
void CancelWhileVerifying() {
    std::mutex mutex; std::condition_variable condition; bool entered = false, release = false;
    ServiceDependencies deps; deps.verify = [&](const Bytes&, const Context&) { std::unique_lock lock(mutex); entered = true; condition.notify_all(); condition.wait(lock, [&] { return release; }); return Verification{std::string(64, '0'), true, 0x0403}; };
    Fixture fixture(1, deps); fixture.Ready(); fixture.service->Command(Attempt(2));
    { std::unique_lock lock(mutex); Check(condition.wait_for(lock, 3s, [&] { return entered; }), "Verification did not start"); }
    fixture.service->Command(Cancel(2));
    { std::lock_guard lock(mutex); release = true; } condition.notify_all();
    const auto value = fixture.Wait("attempt", 2);
    Check(value["cancelled"].isTrue() && value["captured"].isTrue() && value["validationPassed"].isTrue() && value["proof"].isNull(), "Known verification outcome survives cancel; proof withheld");
}
void BudgetAcrossRequestsAndIds() {
    Fixture fixture(1); fixture.Ready();
    auto context = ContextFor(); context.connection_work_target = std::string(64, 'f');
    for (uint64_t id = 2; id <= 4; ++id) { fixture.service->Command(Attempt(id, context)); const auto frame = fixture.Wait("attempt", id); Check(frame["successfulConnections"].get_str() == std::to_string(id - 1), "Shared bounty budget advances"); }
    fixture.service->Command(Attempt(5, context)); const auto blocked = fixture.Wait("attempt", 5);
    Check(blocked["blocked"].get_str() == "budget" && blocked["started"].isFalse(), "Budget stops new TCP");
    Rejects([&] { fixture.service->Command(Attempt(5, context)); });
    context.connection_work_target = std::string(64, '0'); Rejects([&] { fixture.service->Command(Attempt(6, context)); });
    Fixture saturated(1); saturated.Ready(); saturated.service->Command(Attempt(2, ContextFor(), "18446744073709551614"));
    Check(saturated.Wait("attempt", 2)["successfulConnections"].get_str() == "18446744073709551615", "Counter saturates exactly");
    saturated.service->Command(Attempt(3)); Check(saturated.Wait("attempt", 3)["blocked"].get_str() == "budget", "Saturation blocks next start");
}
void OutputFailureStopsBeforeTcp() {
    std::atomic<int> tcp{};
    ServiceDependencies deps; deps.resolve = [](const std::string&) { return std::vector<Endpoint>{{"8.8.8.8", 2, 443}}; };
    deps.capture = [&](const Context&, const Endpoint&, CaptureControl&, const std::function<void()>& started) { started(); ++tcp; return Bytes{2, 1}; };
    deps.verify = [](const Bytes&, const Context&) { return Verification{}; };
    std::mutex mutex; std::condition_variable condition; bool resolved = false;
    ClaimsService service(Json("{\"connectionsPerSecond\":100,\"concurrency\":1}"), [&](const std::string& text) { const auto frame = Json(text); if (frame["type"].get_str() == "started") throw std::runtime_error("Broken writer"); if (frame["type"].get_str() == "resolved") { std::lock_guard lock(mutex); resolved = true; condition.notify_all(); } }, deps);
    service.Command(Resolve(1)); { std::unique_lock lock(mutex); Check(condition.wait_for(lock, 3s, [&] { return resolved; }), "DNS fixture"); }
    service.Command(Attempt(2));
    for (int i = 0; i < 1000 && !service.Failed(); ++i) std::this_thread::sleep_for(1ms);
    Check(service.Failed() && tcp == 0, "Failed start acknowledgement must prevent TCP and fail helper"); service.Close();
}
} // namespace
int main() {
    try { Parsing(); BudgetAndPacing(); SuccessfulAndMissedProof(); FailuresAndDnsCache(); CancelQueuedAndActive(); CancelWhileVerifying(); BudgetAcrossRequestsAndIds(); OutputFailureStopsBeforeTcp(); std::cout << "8 offline service test groups passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
