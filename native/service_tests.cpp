// Offline protocol/lifecycle regression tests. No DNS or sockets are used.
#include <claimer/service.hpp>
#include <claimer/performance_window.hpp>
#include <mbedtls/bignum.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <deque>
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
        if (overrides.performance_time) deps.performance_time = overrides.performance_time;
        if (overrides.dns_time) deps.dns_time = overrides.dns_time;
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
// A pipe-like stream whose producer deliberately stays open between frames.
// A reader that tries to fill a block instead of stopping at newline deadlocks
// the wait-for-response checks below (and the fixture times out).
class InteractiveInput : public std::streambuf {
    std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<std::string> pending_;
    std::string current_;
    bool closed_{};
protected:
    int_type underflow() override {
        if (gptr() < egptr()) return traits_type::to_int_type(*gptr());
        std::unique_lock lock(mutex_);
        condition_.wait(lock, [&] { return closed_ || !pending_.empty(); });
        if (pending_.empty()) return traits_type::eof();
        current_ = std::move(pending_.front()); pending_.pop_front();
        setg(current_.data(), current_.data(), current_.data() + current_.size());
        return traits_type::to_int_type(*gptr());
    }
public:
    void Push(std::string value) {
        Check(!value.empty(), "Interactive test writes nonempty chunks");
        { std::lock_guard lock(mutex_); Check(!closed_, "Interactive test input already closed"); pending_.push_back(std::move(value)); }
        condition_.notify_one();
    }
    void Close() { { std::lock_guard lock(mutex_); closed_ = true; } condition_.notify_all(); }
};
struct CloseAndJoinInput {
    InteractiveInput& input;
    std::thread& consumer;
    ~CloseAndJoinInput() {
        // Closing first wakes a reader blocked between frames. Join before
        // stream/fixture destruction, including when a test assertion throws.
        input.Close();
        if (consumer.joinable()) consumer.join();
    }
};
void InteractiveInputUnwind() {
    InteractiveInput buffer; std::istream stream(&buffer);
    std::atomic<bool> entered{}, exited{};
    std::exception_ptr failure;
    bool unwound = false;
    try {
        std::thread consumer([&] {
            entered = true;
            try { ProtocolFrameReader reader(stream); Check(!reader.Next(), "Unwind must close the empty input"); }
            catch (...) { failure = std::current_exception(); }
            exited = true;
        });
        CloseAndJoinInput close{buffer, consumer};
        for (int i = 0; i < 3000 && !entered; ++i) std::this_thread::sleep_for(1ms);
        Check(entered, "Interactive unwind reader did not start");
        Check(!exited, "Reader must wait while the empty input remains open");
        throw std::runtime_error("Controlled interactive input unwind");
    } catch (const std::runtime_error& error) {
        unwound = std::string(error.what()) == "Controlled interactive input unwind";
        if (!unwound) throw;
    }
    Check(unwound && exited, "Input guard must join its consumer during exception unwinding");
    if (failure) std::rethrow_exception(failure);
}
void Parsing() {
    for (const auto& value : {"{\"a\":1,\"a\":2}\n", "{\"x\":{\"a\":1,\"a\":2}}\n", "{\"x\":NaN}\n", "{}", "[1,]\n"}) {
        Rejects([&] { std::istringstream input(value); ReadFrame(input); });
    }
    Rejects([] { std::istringstream input(std::string(16384, ' ') + "\n"); ReadFrame(input); });
    std::istringstream empty; Check(!ReadFrame(empty), "Clean EOF");
    std::istringstream exact("{}\n{}\n");
    Check(ReadFrame(exact, 3)->isObject() && ReadFrame(exact, 3)->isObject() && !ReadFrame(exact, 3), "Exact frame limit and adjacent frames");
    Rejects([] { std::istringstream input("{}\n"); ReadFrame(input, 2); });
    Rejects([] { std::istringstream input("\n"); ReadFrame(input, 0); });
    Rejects([] { std::istringstream input; input.setstate(std::ios::badbit); ReadFrame(input); });
    Rejects([] { std::istringstream input(std::string("{\"x\":\"a\0b\"}\n", 12)); ReadFrame(input); });
    Rejects([] { std::istringstream input(std::string(65, '[') + "0" + std::string(65, ']') + "\n"); ReadFrame(input); });
    auto context = PublicContext(ContextFor()); Check(ParseContext(context).domain == "example.com", "Public context roundtrip");
    for (const auto& value : {"true", "1.0", "1e0", "-1", "9007199254740992"}) Rejects([&] { ProtocolInteger(Json(value), 1, (uint64_t{1} << 53) - 1); });
    for (const auto& value : {"LOCALHOST", "x.local", "x.internal", "x.localhost", "example.com.", "a..com"}) Rejects([&] { PublicDomain(UniValue(value)); });
}
void BufferedFrameBoundaries() {
    // Size includes the delimiter, for both the regular and one-shot limits.
    for (const size_t maximum : {size_t{3}, size_t{16}, size_t{16384}, size_t{160 * 1024}}) {
        const std::string exact = "{}" + std::string(maximum - 3, ' ') + "\n";
        std::istringstream stream(exact + "{}\n"); ProtocolFrameReader reader(stream);
        Check(reader.Next(maximum)->isObject(), "Exact buffered frame limit accepted");
        Check(reader.Next(3)->isObject() && !reader.Next(3), "No consumed successor bytes when changing frame limits");
        Rejects([&] { std::istringstream input(" " + exact); ProtocolFrameReader(input).Next(maximum); });
        Rejects([&] { std::istringstream input(exact.substr(0, exact.size() - 1)); ProtocolFrameReader(input).Next(maximum); });
    }
    Rejects([] { std::istringstream input("{}\n"); ProtocolFrameReader(input).Next(160 * 1024 + 1); });
    std::istringstream crlf("{}\r\n{}\n"); ProtocolFrameReader reader(crlf);
    Check(reader.Next(4)->isObject() && reader.Next(3)->isObject(), "CRLF and LF are both bounded delimiters");
    std::string large = "{";
    for (unsigned i = 0; i < 100; ++i) large += (i ? "," : "") + std::string("\"key") + std::to_string(i) + "\":0";
    Check(Json(large + "}").size() == 100, "Large object unique keys accepted");
    Rejects([&] { Json(large + ",\"key0\":1}"); });
    Rejects([] { Json("{\"a\":1,\"\\u0061\":2}"); });
    Rejects([] { Json("{\"items\":[{\"x\":1,\"x\":2}]}"); });
    std::istringstream errors("{}\n"); ProtocolFrameReader error_reader(errors);
    errors.setstate(std::ios::failbit); Rejects([&] { error_reader.Next(); });
    errors.clear(); errors.setstate(std::ios::badbit | std::ios::eofbit); Rejects([&] { error_reader.Next(); });
}
void InteractiveFrameCancellation() {
    ServiceDependencies deps;
    deps.capture = [](const Context&, const Endpoint&, CaptureControl& control, const std::function<void()>& started) -> Bytes {
        started(); while (!control.Cancelled()) std::this_thread::sleep_for(1ms); throw CaptureCancelled();
    };
    Fixture fixture(1, deps); fixture.Ready();
    InteractiveInput buffer; std::istream stream(&buffer); std::exception_ptr failure;
    std::thread consumer([&] {
        try { ProtocolFrameReader reader(stream); while (auto command = reader.Next()) fixture.service->Command(*command); }
        catch (...) { failure = std::current_exception(); }
    });
    CloseAndJoinInput close{buffer, consumer};
    const auto attempt = Attempt(2).write();
    buffer.Push(attempt.substr(0, attempt.size() / 2));
    buffer.Push(attempt.substr(attempt.size() / 2) + "\n");
    fixture.Wait("started", 2); // The pipe is still open, not a full 16 KiB.
    buffer.Push(Cancel(2).write() + "\n");
    const auto cancelled = fixture.Wait("attempt", 2);
    Check(cancelled["cancelled"].isTrue() && cancelled["started"].isTrue() && cancelled["validationPassed"].isNull(),
          "Interactive cancellation is processed without filling a block or waiting for EOF");
    Check(cancelled["successfulConnections"].get_str() == "0", "Interactive cancellation cannot invent a capture");
    buffer.Close(); consumer.join(); if (failure) std::rethrow_exception(failure);
}
void NativePreparedContextReuse() {
    std::mutex mutex; std::condition_variable condition; std::vector<UniValue> frames;
    UniValue options(UniValue::VOBJ); options.pushKV("connectionsPerSecond", 1000); options.pushKV("concurrency", 1);
    // The real native admission path, but no resolve commands: every attempt
    // ends at the missing-DNS guard, without making any network connection.
    ClaimsService service(options, [&](const std::string& text) {
        UniValue value; Check(value.read(text), "Native cache response JSON");
        { std::lock_guard lock(mutex); frames.push_back(std::move(value)); } condition.notify_one();
    });
    uint64_t id = 0;
    auto admit = [&](const Context& context) {
        const auto request_id = ++id; service.Command(Attempt(request_id, context));
        std::unique_lock lock(mutex);
        const auto matches = [&](const UniValue& value) { return value["id"].getInt<uint64_t>() == request_id; };
        Check(condition.wait_for(lock, 3s, [&] { return std::any_of(frames.begin(), frames.end(), matches); }), "Cached-context response timeout");
        const auto& frame = *std::find_if(frames.begin(), frames.end(), matches);
        Check(frame["context"].write() == PublicContext(context).write(), "Response retains each job's complete current context");
        Check(frame["started"].isFalse() && frame["captured"].isFalse() && frame["validationPassed"].isNull(), "Cache test cannot open a socket or invent validation");
    };
    auto context = ContextFor(); admit(context); admit(context);
    context.validation_time = 1; admit(context);
    context.validation_time = 253402300799; admit(context);
    context.domain = "other.example"; admit(context);
    context.txid = std::string(64, 'b'); admit(context);
    context.input_index = 0xffffffff; admit(context);
    context.signature_algorithms_mask = 2; admit(context);
    auto rejects_context = [&](Context changed) { Rejects([&] { service.Command(Attempt(id + 1, changed)); }); admit(context); };
    auto changed = context; changed.domain = "not a domain"; rejects_context(changed);
    changed = context; changed.txid = std::string(64, 'A'); rejects_context(changed);
    changed = context; changed.txid.resize(63); rejects_context(changed);
    changed = context; changed.connection_work_target = std::string(64, 'g'); rejects_context(changed);
    changed = context; changed.connection_work_target = std::string(64, 'f'); rejects_context(changed); // Existing budget rule.
    changed = context; changed.root_certificates_version = 2; rejects_context(changed);
    changed = context; changed.signature_algorithms_mask = 0; rejects_context(changed);
    changed = context; changed.validation_time = 0; rejects_context(changed);
    changed = context; changed.validation_time = 253402300800; rejects_context(changed);
    service.Close(); Check(!service.Failed(), "Malformed cache replacements never corrupt live service state");
}
struct Mpi {
    mbedtls_mpi value;
    Mpi() { mbedtls_mpi_init(&value); }
    ~Mpi() { mbedtls_mpi_free(&value); }
    Mpi(const Mpi&) = delete;
    Mpi& operator=(const Mpi&) = delete;
};
bool OracleBudgetExhausted(const std::string& target, uint64_t successes) {
    if (successes == UINT64_MAX) return true;
    Mpi factor, count, product, limit;
    std::array<unsigned char, 8> bytes{};
    for (size_t i = 0; i < bytes.size(); ++i) bytes[7 - i] = static_cast<unsigned char>(successes >> (8 * i));
    Check(mbedtls_mpi_read_string(&factor.value, 16, target.c_str()) == 0 &&
          mbedtls_mpi_add_int(&factor.value, &factor.value, 1) == 0 &&
          mbedtls_mpi_read_binary(&count.value, bytes.data(), bytes.size()) == 0 &&
          mbedtls_mpi_mul_mpi(&product.value, &factor.value, &count.value) == 0 &&
          mbedtls_mpi_lset(&limit.value, 1) == 0 &&
          mbedtls_mpi_shift_l(&limit.value, 257) == 0, "Independent budget oracle setup");
    return mbedtls_mpi_cmp_mpi(&product.value, &limit.value) > 0;
}
void PrecomputedBudgetBoundaries() {
    // All powers of two exercise exact equality on every limb, including the
    // 257-bit factor and budgets larger than the entire uint64 counter range.
    for (size_t bit = 0; bit <= 256; ++bit) {
        std::array<unsigned char, 32> bytes{};
        for (size_t low = 0; low < bit; ++low) bytes[31 - low / 8] |= static_cast<unsigned char>(1u << (low % 8));
        const auto target = Hex(bytes);
        const auto stop = ConnectionBudgetStopCount(target);
        const size_t quotient_bit = 257 - bit;
        const auto expected = quotient_bit >= 64 ? UINT64_MAX : (uint64_t{1} << quotient_bit) + 1;
        Check(stop == expected, "Precomputed power-of-two budget boundary");
        Check(!OracleBudgetExhausted(target, stop - 1) && OracleBudgetExhausted(target, stop), "Exact boundary matches independent oracle");
    }
    uint64_t random = 0x912ab735c6418defULL;
    auto next = [&] { random ^= random << 13; random ^= random >> 7; random ^= random << 17; return random; };
    for (size_t example = 0; example < 512; ++example) {
        std::array<unsigned char, 32> bytes{};
        for (size_t i = example % 33; i < bytes.size(); ++i) bytes[i] = static_cast<unsigned char>(next());
        const auto target = Hex(bytes);
        const auto stop = ConnectionBudgetStopCount(target);
        const std::array<uint64_t, 8> counts{0, 1, stop - 1, stop, stop == UINT64_MAX ? stop : stop + 1, UINT64_MAX - 1, UINT64_MAX, next()};
        for (const auto count : counts) {
            const bool oracle = OracleBudgetExhausted(target, count);
            Check((count >= stop) == oracle, "Cached budget matches independent arbitrary-precision oracle");
            Check(ConnectionBudgetExhausted(target, count) == oracle, "Original product comparator matches independent oracle");
        }
    }
    for (const auto& target : {std::string(), std::string(63, '0'), std::string(66, '0'), std::string(64, 'A'), std::string(64, 'z')})
        Rejects([&] { ConnectionBudgetStopCount(target); });
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
void ConcurrentCaptureSnapshotsRemainImmutable() {
    std::mutex gate;
    std::condition_variable condition;
    unsigned verifying = 0;
    ServiceDependencies deps;
    deps.verify = [&](const Bytes&, const Context&) {
        std::unique_lock lock(gate);
        ++verifying; condition.notify_all();
        Check(condition.wait_for(lock, 3s, [&] { return verifying == 8; }), "All concurrent captures reach verification");
        return Verification{std::string(64, 'f'), false, 0x0403};
    };
    Fixture fixture(8, deps); fixture.Ready();
    for (uint64_t id = 2; id < 10; ++id) fixture.service->Command(Attempt(id));
    std::vector<uint64_t> counts;
    for (uint64_t id = 2; id < 10; ++id) {
        const auto capture = fixture.Wait("capture", id), final = fixture.Wait("attempt", id);
        Check(capture["successfulConnections"].get_str() == final["successfulConnections"].get_str(), "Concurrent terminal uses its own capture snapshot");
        Check(final["validationPassed"].isTrue(), "All concurrent proofs verified");
        counts.push_back(std::stoull(final["successfulConnections"].get_str()));
    }
    std::sort(counts.begin(), counts.end());
    Check(counts == std::vector<uint64_t>{1, 2, 3, 4, 5, 6, 7, 8}, "Concurrent captures increment budget exactly once");
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
void BudgetCountsInvalidCapturesAndMonotonicReports() {
    ServiceDependencies deps;
    deps.verify = [](const Bytes&, const Context&) -> Verification { throw std::runtime_error("Invalid proof"); };
    Fixture fixture(1, deps); fixture.Ready();
    auto context = ContextFor(); context.connection_work_target = std::string(64, 'f');
    // Equality (2 captures) still permits one more TCP; a captured invalid proof
    // also spends that slot. A stale controller report must not reopen it.
    fixture.service->Command(Attempt(2, context, "2"));
    const auto invalid = fixture.Wait("attempt", 2);
    Check(invalid["started"].isTrue() && invalid["captured"].isTrue() && invalid["validationPassed"].isFalse(), "Invalid proof remains a conclusive captured attempt");
    Check(invalid["successfulConnections"].get_str() == "3", "Invalid raw capture still spends exact budget");
    fixture.service->Command(Attempt(3, context, "0"));
    const auto stale = fixture.Wait("attempt", 3);
    Check(stale["blocked"].get_str() == "budget" && stale["successfulConnections"].get_str() == "3" && stale["started"].isFalse(), "Stale count cannot undo cached budget exhaustion");
    Check(fixture.captures == 1, "No socket after the cached budget is spent");

    Fixture reported(1); reported.Ready();
    reported.service->Command(Attempt(2, context, "3"));
    const auto blocked = reported.Wait("attempt", 2);
    Check(blocked["blocked"].get_str() == "budget" && !reported.captures, "Already exhausted imported budget does not start TCP");
}
void EndpointSelectionBoundAndRoundRobin() {
    std::mutex mutex;
    std::vector<std::string> seen;
    ServiceDependencies deps;
    deps.resolve = [](const std::string&) {
        std::vector<Endpoint> endpoints;
        for (size_t i = 1; i <= 40; ++i) endpoints.push_back({"8.8.8." + std::to_string(i), 2, 443});
        return endpoints;
    };
    // An inconclusive cancellation does not change performance, leaving equal
    // credits so the fixed-size selection storage can be checked exactly.
    deps.capture = [&](const Context&, const Endpoint& endpoint, CaptureControl&, const std::function<void()>&) -> Bytes {
        { std::lock_guard lock(mutex); seen.push_back(endpoint.ip); }
        throw CaptureCancelled();
    };
    Fixture fixture(1, deps); fixture.Ready();
    for (uint64_t id = 2; id < 66; ++id) {
        fixture.service->Command(Attempt(id));
        const auto value = fixture.Wait("attempt", id);
        Check(value["started"].isFalse() && value["validationPassed"].isNull(), "Selection-only fixture spends no counter");
    }
    std::lock_guard lock(mutex);
    Check(seen.size() == 64, "All bounded selections completed");
    for (size_t i = 0; i < seen.size(); ++i) Check(seen[i] == "8.8.8." + std::to_string(i % 32 + 1), "First 32 endpoints retain exact equal-weight round robin");
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
void PerformanceMinuteBoundariesAndGaps() {
    MinutePerformanceWindow window;
    Check(window.Record(true, 0.25, 59.999), "Record first bucket");
    Check(window.Record(false, 0.75, 60), "Record next minute failure");
    auto totals = window.Read(3599.999);
    Check(totals.attempts == 2 && totals.valid == 1 && totals.seconds == 1, "Current plus previous 59 minutes retained");
    totals = window.Read(3600);
    Check(totals.attempts == 1 && totals.valid == 0 && totals.seconds == 0.75, "Old minute expires on read, not just a new connection");
    totals = window.Read(0);
    Check(totals.attempts == 1 && totals.seconds == 0.75, "Backwards clock cannot resurrect expired bucket");
    Check(window.Record(true, 0.125, 120), "Backwards record assigned to latest minute");
    totals = window.Read(3660);
    Check(totals.attempts == 1 && totals.valid == 1 && totals.seconds == 0.125, "Backwards record remains in current minute");
    totals = window.Read(7200);
    Check(!totals.attempts && !totals.valid && totals.seconds == 0, "Hour gap clears all samples exactly");
    Check(window.Record(true, 0, 7200), "Zero measured elapsed time is a valid observation");
    Check(window.Record(false, 2, 10800), "Record also expires old samples");
    totals = window.Read(10800);
    Check(totals.attempts == 1 && !totals.valid && totals.seconds == 2, "Record-after-gap keeps only fresh failure");
    Check(!window.Record(true, -1, 10800) && !window.Record(true, INFINITY, 10800) && !window.Record(true, NAN, 10800), "Invalid durations do not become samples");
    totals = window.Read(10800);
    Check(totals.attempts == 1 && totals.seconds == 2, "Rejected observations leave totals unchanged");
    Rejects([&] { window.Read(NAN); }); Rejects([&] { window.Read(-1); });
    Rejects([&] { window.Read(INFINITY); }); Rejects([&] { window.Read(1e300); });
    MinutePerformanceWindow ring;
    for (int64_t minute = 0; minute < 6000; ++minute) {
        Check(ring.Record(minute % 2 == 0, 0.125, minute * 60.0), "Many bounded rotations recorded");
        const auto count = static_cast<uint64_t>(std::min<int64_t>(minute + 1, 60));
        const auto current = ring.Read(minute * 60.0);
        Check(current.attempts == count && current.valid <= count && current.seconds == count * 0.125, "Ring totals match retained bucket count");
    }
    Check(ring.Read(6000 * 60.0).attempts == 59, "Idle read advances rolling totals");
    MinutePerformanceWindow precision;
    precision.Record(true, 1e16, 0); precision.Record(true, 0.125, 60);
    const auto small_remaining = precision.Read(3600);
    Check(small_remaining.attempts == 1 && small_remaining.seconds == 0.125, "Expiring large totals cannot erase smaller retained sample duration");
}
void PerformanceCacheBoundsAndConservativeExpiry() {
    EndpointPerformanceCache cache(2);
    const auto a = std::make_shared<EndpointPerformanceScore>(), b = std::make_shared<EndpointPerformanceScore>(), c = std::make_shared<EndpointPerformanceScore>();
    const auto minimum = std::numeric_limits<double>::denorm_min();
    Check(cache.Rate(a, 0) == 5 && cache.Size() == 0, "Never observed prior allocates no history");
    a->credit = 0.375;
    Check(cache.Record(a, true, 0.5, 0) && cache.Rate(a, 0) == 2, "Fresh ratio uses actual conclusive sample");
    Check(cache.Record(b, false, 1, 1) && cache.Rate(b, 1) == minimum, "Failed validation counts as time without a valid proof");
    Check(cache.Record(a, true, 0.5, 2), "Conclusive observation updates LRU order");
    Check(cache.Record(c, true, 0, 3), "Third score evicts oldest history at cap");
    Check(cache.Size() == 2 && cache.Rate(b, 3) == minimum && cache.Rate(a, 3) == 2, "Eviction retains observed state, no optimistic reset");
    Check(cache.Rate(c, 3) == std::numeric_limits<double>::max(), "Zero-time valid sample remains finite maximum");
    Check(cache.Rate(a, 3600) == minimum && cache.Size() == 0 && a->credit == 0.375, "Expiry frees histories without resetting rotation credit");
    Check(cache.Rate(a, 0) == minimum, "Backwards cache clock does not restore prior");
    Check(cache.Record(a, true, 0.25, 0) && cache.Rate(a, 3600) == 4, "Fresh recovery observation can replace expired history");
    Check(cache.Rate(a, 7199.999) == 4 && cache.Rate(a, 7200) == minimum, "Backwards record honors clamped current cache minute");
    Check(!cache.Record(b, true, NAN, 7200) && cache.Size() == 0, "Invalid sample does not allocate a history");
    std::vector<std::shared_ptr<EndpointPerformanceScore>> held;
    for (int i = 0; i < 10000; ++i) {
        held.push_back(std::make_shared<EndpointPerformanceScore>());
        Check(cache.Record(held.back(), true, 1, 7200) && cache.Size() <= 2, "Even running jobs holding old scores cannot exceed cache bound");
    }
    Check(cache.Rate(held.front(), 7200) == minimum && cache.Rate(held.back(), 7200) == 1, "Evicted active-job score remains safe to read");
    Check(cache.Record(held.front(), false, 1, 7200) && cache.Size() == 2, "Previously evicted score can record without stale iterator use");
    Check(cache.Rate(held.back(), 10800) == minimum && cache.Size() == 0, "Bulk stale cleanup is bounded and frees all histories");
    auto survivor = std::make_shared<EndpointPerformanceScore>();
    { EndpointPerformanceCache temporary; temporary.Record(survivor, true, 1, 0); }
    Check(cache.Rate(survivor, 10800) == minimum && cache.Record(survivor, true, 0.5, 10800), "Cache destruction leaves externally held scores safely reusable");
}
void PerformanceSurvivesSameIpDnsRefreshAndKeepsBudgets() {
    std::atomic<double> dns_now{0}, performance_now{0};
    std::atomic<int> bad{}, good{};
    ServiceDependencies deps;
    deps.dns_time = [&] { return dns_now.load(); };
    deps.performance_time = [&] { return performance_now.load(); };
    deps.capture = [&](const Context&, const Endpoint& endpoint, CaptureControl&, const std::function<void()>& started) -> Bytes {
        if (endpoint.ip == "8.8.8.8") { ++bad; started(); throw CaptureTimeout(); }
        ++good; throw CaptureCancelled(); // Unknown score, no fabricated validation result.
    };
    Fixture fixture(1, deps); fixture.Ready();
    for (uint64_t id = 2; id < 52; ++id) {
        fixture.service->Command(Attempt(id));
        Check(fixture.Wait("attempt", id)["successfulConnections"].get_str() == "0", "Failed/inconclusive attempt does not reset or fabricate capture budget");
    }
    Check(bad == 1 && good == 49, "Observed failing endpoint loses performance share, with exploration retained");
    const auto previous_good = good.load();
    dns_now = 60;
    fixture.service->Command(Resolve(52)); Check(fixture.Wait("resolved", 52)["ok"].isTrue() && fixture.resolutions == 2, "DNS refreshed on exact deadline");
    for (uint64_t id = 53; id < 103; ++id) { fixture.service->Command(Attempt(id)); fixture.Wait("attempt", id); }
    Check(good - previous_good >= 49, "Same-IP refresh preserves failure window and 99/1 selection credit");
    performance_now = 3600;
    for (uint64_t id = 103; id < 113; ++id) { fixture.service->Command(Attempt(id)); fixture.Wait("attempt", id); }
    Check(fixture.verifications == 0, "Performance expiration never fabricates validation or proof");

    ServiceDependencies success;
    success.performance_time = [&] { return performance_now.load(); };
    Fixture budget(1, success); budget.Ready();
    auto context = ContextFor(); context.connection_work_target = std::string(64, 'f');
    budget.service->Command(Attempt(2, context, "2"));
    Check(budget.Wait("attempt", 2)["successfulConnections"].get_str() == "3", "Successful capture consumes final bounty slot");
    performance_now = 100000;
    budget.service->Command(Attempt(3, context)); const auto blocked = budget.Wait("attempt", 3);
    Check(blocked["blocked"].get_str() == "budget" && blocked["successfulConnections"].get_str() == "3" && blocked["started"].isFalse(), "Expired IP window cannot reopen bounty budget or erase lifetime counter");
}
} // namespace
int main() {
    try { Parsing(); BufferedFrameBoundaries(); InteractiveInputUnwind(); InteractiveFrameCancellation(); NativePreparedContextReuse(); BudgetAndPacing(); PrecomputedBudgetBoundaries(); SuccessfulAndMissedProof(); ConcurrentCaptureSnapshotsRemainImmutable(); FailuresAndDnsCache(); CancelQueuedAndActive(); CancelWhileVerifying(); BudgetAcrossRequestsAndIds(); BudgetCountsInvalidCapturesAndMonotonicReports(); EndpointSelectionBoundAndRoundRobin(); OutputFailureStopsBeforeTcp(); UnreachableEndpointIsExcludedAcrossMasksAndDomains(); UnsupportedFamilyAndTimedRecovery(); RouteRecoveryAndOrdinaryFailures(); QueuedEndpointRecheckedAndCancellationDoesNotExclude(); PerformanceMinuteBoundariesAndGaps(); PerformanceCacheBoundsAndConservativeExpiry(); PerformanceSurvivesSameIpDnsRefreshAndKeepsBudgets(); std::cout << "23 offline service test groups passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
