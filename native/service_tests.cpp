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
        if (overrides.reachability_time) deps.reachability_time = overrides.reachability_time;
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
void UnreachableEndpointIsExcludedAcrossMasksAndDomains() {
    std::atomic<int> bad{}, good{};
    ServiceDependencies deps;
    deps.capture = [&](const Context&, const Endpoint& endpoint, CaptureControl&, const std::function<void()>& started) -> Bytes {
        started();
        if (endpoint.ip == "8.8.8.8") { ++bad; throw LocalEndpointUnavailable(false); }
        ++good; return Bytes{2, 1};
    };
    Fixture fixture(1, deps); fixture.Ready(); fixture.service->Command(Attempt(2));
    const auto failed = fixture.Wait("attempt", 2);
    Check(failed["started"].isTrue() && failed["validationPassed"].isFalse() && failed["captured"].isFalse(), "Actual unreachable TCP remains a failed attempt");
    Check(failed["successfulConnections"].get_str() == "0", "Unreachable route spends no successful capture budget");
    for (uint64_t id = 3; id < 10; ++id) {
        fixture.service->Command(Attempt(id, ContextFor(id % 2 ? 6 : 7)));
        Check(fixture.Wait("attempt", id)["validationPassed"].isTrue(), "Another address in the same family must stay available");
    }
    fixture.service->Command(Resolve(10, "other.example")); Check(fixture.Wait("resolved", 10)["ok"].isTrue(), "Other domain has a usable endpoint");
    auto context = ContextFor(); context.domain = "other.example";
    for (uint64_t id = 11; id < 15; ++id) { fixture.service->Command(Attempt(id, context)); Check(fixture.Wait("attempt", id)["validationPassed"].isTrue(), "Exclusion survives domain changes"); }
    Check(bad == 1 && good == 11 && fixture.verifications == 11, "Impossible IP excluded immediately; all good captures still verified");
}
void UnsupportedFamilyAndTimedRecovery() {
    std::atomic<int> unavailable{};
    std::atomic<double> now{100};
    std::atomic<bool> supported{false};
    ServiceDependencies deps;
    deps.reachability_time = [&] { return now.load(); };
    deps.resolve = [](const std::string& domain) { return std::vector<Endpoint>{{domain == "example.com" ? "2001:4860:4860::8888" : "2606:4700:4700::1111", 10, 443}}; };
    deps.capture = [&](const Context&, const Endpoint&, CaptureControl&, const std::function<void()>& started) -> Bytes {
        if (!supported) { ++unavailable; throw LocalEndpointUnavailable(true); }
        started(); return Bytes{2, 1};
    };
    Fixture fixture(1, deps); fixture.Ready(); fixture.service->Command(Attempt(2));
    const auto failed = fixture.Wait("attempt", 2);
    Check(failed["started"].isFalse() && failed["validationPassed"].isNull(), "Unsupported socket family spends no TCP counter");
    now = 159;
    fixture.service->Command(Attempt(3)); Check(fixture.Wait("attempt", 3)["started"].isFalse(), "Cached exclusion prevents capture");
    fixture.service->Command(Resolve(4)); Check(fixture.Wait("resolved", 4)["ok"].isFalse(), "All excluded tells controller to back off, not spin");
    fixture.service->Command(Resolve(5, "other.example")); Check(fixture.Wait("resolved", 5)["ok"].isFalse(), "Unsupported family blocked across new DNS addresses");
    Check(unavailable == 1, "Cached exclusions do not invoke capture or renew deadline");
    supported = true; now = 160;
    fixture.service->Command(Resolve(6)); Check(fixture.Wait("resolved", 6)["ok"].isTrue(), "Family re-enabled exactly at the monotonic deadline");
    fixture.service->Command(Attempt(7)); Check(fixture.Wait("attempt", 7)["validationPassed"].isTrue(), "Recovered family must capture and fully verify");
    Check(fixture.verifications == 1, "Recovery retains proof validation");
}
void RouteRecoveryAndOrdinaryFailures() {
    std::atomic<double> now{10}; std::atomic<bool> reachable{false}; std::atomic<int> captures{};
    ServiceDependencies deps;
    deps.reachability_time = [&] { return now.load(); };
    deps.resolve = [](const std::string&) { return std::vector<Endpoint>{{"8.8.8.8", 2, 443}}; };
    deps.capture = [&](const Context&, const Endpoint&, CaptureControl&, const std::function<void()>& started) -> Bytes {
        ++captures; started(); if (!reachable) throw LocalEndpointUnavailable(false); return Bytes{2, 1};
    };
    Fixture fixture(1, deps); fixture.Ready(); fixture.service->Command(Attempt(2)); fixture.Wait("attempt", 2);
    now = 69; fixture.service->Command(Resolve(3)); Check(fixture.Wait("resolved", 3)["ok"].isFalse(), "Single unreachable endpoint excluded");
    fixture.service->Command(Attempt(4)); const auto blocked = fixture.Wait("attempt", 4);
    Check(blocked["started"].isFalse() && blocked["validationPassed"].isNull() && captures == 1, "Exclusion itself is not another failure or TCP attempt");
    now = 70; reachable = true;
    fixture.service->Command(Resolve(5)); Check(fixture.Wait("resolved", 5)["ok"].isTrue(), "Route exclusion expires without new DNS");
    fixture.service->Command(Attempt(6)); Check(fixture.Wait("attempt", 6)["validationPassed"].isTrue() && captures == 2, "Recovered IP is probed again");
    deps.capture = [&](const Context&, const Endpoint&, CaptureControl&, const std::function<void()>& started) -> Bytes { ++captures; started(); throw CaptureTimeout(); };
    Fixture ordinary(1, deps); ordinary.Ready();
    for (uint64_t id = 2; id < 6; ++id) { ordinary.service->Command(Attempt(id)); Check(ordinary.Wait("attempt", id)["started"].isTrue(), "Timeout does not declare a family or route impossible"); }
    Check(captures == 6, "Normal transient failures keep ordinary selection policy");
}
void QueuedEndpointRecheckedAndCancellationDoesNotExclude() {
    std::mutex gate; std::condition_variable cv;
    int entered = 0; bool first_done = false;
    std::atomic<int> starts{};
    ServiceDependencies deps;
    deps.resolve = [](const std::string&) { return std::vector<Endpoint>{{"8.8.8.8", 2, 443}}; };
    deps.capture = [&](const Context&, const Endpoint&, CaptureControl&, const std::function<void()>& started) -> Bytes {
        std::unique_lock lock(gate); const int order = ++entered; cv.notify_all();
        if (order == 1) { Check(cv.wait_for(lock, 2s, [&] { return entered == 2; }), "Second worker did not select endpoint"); lock.unlock(); started(); ++starts; throw LocalEndpointUnavailable(false); }
        Check(cv.wait_for(lock, 2s, [&] { return first_done; }), "First route failure not recorded"); lock.unlock();
        started(); ++starts; return Bytes{2, 1};
    };
    Fixture fixture(2, deps); fixture.Ready(); fixture.service->Command(Attempt(2)); fixture.service->Command(Attempt(3));
    // IDs need not enter the fake capture in dispatch order.
    for (int i = 0; i < 2000; ++i) {
        bool terminal = false;
        { std::lock_guard lock(fixture.mutex); terminal = std::any_of(fixture.frames.begin(), fixture.frames.end(), [](const auto& frame) { return frame["type"].get_str() == "attempt"; }); }
        if (terminal) break;
        std::this_thread::sleep_for(1ms);
    }
    { std::lock_guard lock(gate); first_done = true; } cv.notify_all();
    const auto a = fixture.Wait("attempt", 2), b = fixture.Wait("attempt", 3);
    Check(starts == 1 && a["started"].isTrue() != b["started"].isTrue(), "Already-selected queued worker must not open excluded endpoint");
    Check(fixture.verifications == 0, "No imaginary proof validation for skipped capture");

    std::atomic<bool> cancel_entered{false}; std::atomic<int> attempts{};
    deps.capture = [&](const Context&, const Endpoint&, CaptureControl& control, const std::function<void()>& started) -> Bytes {
        if (++attempts == 1) { cancel_entered = true; while (!control.Cancelled()) std::this_thread::sleep_for(1ms); throw LocalEndpointUnavailable(true); }
        started(); return Bytes{2, 1};
    };
    Fixture cancelled(1, deps); cancelled.Ready(); cancelled.service->Command(Attempt(2));
    for (int i = 0; i < 2000 && !cancel_entered; ++i) std::this_thread::sleep_for(1ms);
    Check(cancel_entered, "Cancellation capture did not enter"); cancelled.service->Command(Cancel(2));
    Check(cancelled.Wait("attempt", 2)["cancelled"].isTrue(), "Cancellation reported");
    cancelled.service->Command(Resolve(3)); Check(cancelled.Wait("resolved", 3)["ok"].isTrue(), "Cancelled failure does not poison family availability");
    cancelled.service->Command(Attempt(4)); Check(cancelled.Wait("attempt", 4)["validationPassed"].isTrue(), "Capture after cancellation remains usable");
}
} // namespace
int main() {
    try { Parsing(); BudgetAndPacing(); SuccessfulAndMissedProof(); FailuresAndDnsCache(); CancelQueuedAndActive(); CancelWhileVerifying(); BudgetAcrossRequestsAndIds(); OutputFailureStopsBeforeTcp(); UnreachableEndpointIsExcludedAcrossMasksAndDomains(); UnsupportedFamilyAndTimedRecovery(); RouteRecoveryAndOrdinaryFailures(); QueuedEndpointRecheckedAndCancellationDoesNotExclude(); std::cout << "12 offline service test groups passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
