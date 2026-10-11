// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#include <claimer/service.hpp>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <mutex>
#include <thread>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace {
using namespace claimer;
using Clock = std::chrono::steady_clock;
void EmitFrame(const std::string& text) {
    if (text.size() > 160 * 1024) throw std::runtime_error("Helper response exceeds size limit");
    std::cout << text << '\n' << std::flush;
    if (!std::cout) throw std::runtime_error("Helper output failed");
}
UniValue Frame(std::string_view type) { UniValue value(UniValue::VOBJ); value.pushKV("type", std::string(type)); return value; }
UniValue RequiredFrame(size_t maximum = 16384) {
    auto value = ReadFrame(std::cin, maximum);
    if (!value) throw std::invalid_argument("Protocol request required");
    return *value;
}
int VerifyOffline() {
    const auto request = RequiredFrame(160 * 1024);
    ExactKeys(request, {"context", "proof"});
    const auto context = ParseContext(request["context"]);
    const auto proof = Unhex(request["proof"].get_str());
    if (proof.size() > 64 * 1024 || std::cin.peek() != std::char_traits<char>::eof()) throw std::invalid_argument("Invalid offline proof request");
    InitializeCrypto();
    auto response = Frame("verification");
    try {
        const auto verified = VerifyProof(proof, context);
        response.pushKV("validationPassed", true); response.pushKV("meetsTarget", verified.meets_target);
        response.pushKV("connectionWorkHash", verified.work_hash); response.pushKV("signatureScheme", verified.signature_scheme);
    } catch (...) { response.pushKV("validationPassed", false); response.pushKV("meetsTarget", false); }
    EmitFrame(response.write());
    return 0;
}
int Probe() {
    struct State { std::mutex mutex; std::condition_variable condition; bool done{}, verified{}; std::optional<UniValue> request; CaptureControl control; };
    auto state = std::make_shared<State>();
    const auto deadline = Clock::now() + std::chrono::seconds(3);
    std::thread worker([state, deadline] {
        try {
            const auto request = RequiredFrame(1024);
            ExactKeys(request, {"domain", "rootVersion", "validationTime"});
            const auto domain = PublicDomain(request["domain"]);
            // A capability probe only accepts a DNS name, never an IP literal.
            if (domain.ends_with(".home.arpa") || domain.find_first_not_of("0123456789.") == std::string::npos) throw std::invalid_argument("Invalid probe domain");
            ProtocolInteger(request["rootVersion"], 1, 1);
            const auto moment = ProtocolInteger(request["validationTime"], 1, 253402300799);
            if (std::cin.peek() != std::char_traits<char>::eof()) throw std::invalid_argument("Unexpected probe frame");
            { std::lock_guard lock(state->mutex); state->request = request; }
            InitializeCrypto();
            const auto endpoints = ResolveEndpoints(domain);
            if (endpoints.empty() || Clock::now() >= deadline || state->control.Cancelled()) throw CaptureTimeout();
            Hash random{}; RandomBytes(random);
            Context context{domain, Hex(random), 0, std::string(64, 'f'), 1, 6, static_cast<int64_t>(moment)};
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
            const auto proof = Capture(context, endpoints.front(), state->control, {}, remaining, true);
            VerifyProof(proof, context);
            std::lock_guard lock(state->mutex); state->verified = Clock::now() < deadline && !state->control.Cancelled();
        } catch (...) {}
        { std::lock_guard lock(state->mutex); state->done = true; } state->condition.notify_all();
    });
    UniValue response;
    bool done;
    { std::unique_lock lock(state->mutex);
        state->condition.wait_until(lock, deadline, [&] { return state->done; }); done = state->done;
        if (state->request) { response = *state->request; response.pushKV("type", "rsa-probe"); response.pushKV("verified", done && state->verified && Clock::now() < deadline); }
        else { response = Frame("error"); response.pushKV("message", "Invalid or incomplete RSA probe request."); }
    }
    state->control.Cancel();
    if (done) worker.join(); else worker.detach();
    EmitFrame(response.write());
    const int status = response["type"].get_str() == "error" ? 1 : 0;
    // An OS resolver/read may not be interruptible. This one-shot process has
    // already flushed its only response; avoid destruction racing its worker.
    if (!done) std::_Exit(status);
    return status;
}
int Generate() {
    const auto request = RequiredFrame();
    ExactKeys(request, {"context", "options"});
    const auto context = ParseContext(request["context"]);
    const auto& options = request["options"];
    ExactKeys(options, {"connectionsPerSecond", "concurrency", "overallTimeout", "maxAttempts"});
    const auto rate = ProtocolInteger(options["connectionsPerSecond"], 1, 2147483647);
    const auto concurrency = ProtocolInteger(options["concurrency"], 1, 2147483647);
    const auto timeout = ProtocolInteger(options["overallTimeout"], 1, 600);
    const auto limit = ProtocolInteger(options["maxAttempts"], 1, 100000);
    InitializeCrypto();
    UniValue service_options(UniValue::VOBJ); service_options.pushKV("connectionsPerSecond", rate); service_options.pushKV("concurrency", concurrency);
    std::mutex mutex; std::condition_variable condition; std::deque<UniValue> received;
    ClaimsService service(service_options, [&](const std::string& text) { UniValue value; if (!value.read(text)) throw std::runtime_error("Internal JSON error"); { std::lock_guard lock(mutex); received.push_back(std::move(value)); } condition.notify_all(); });
    const auto begin = Clock::now(), deadline = begin + std::chrono::seconds(timeout);
    auto next = [&]() -> std::optional<UniValue> {
        std::unique_lock lock(mutex);
        if (!condition.wait_until(lock, deadline, [&] { return !received.empty(); })) return std::nullopt;
        auto frame = std::move(received.front()); received.pop_front(); return frame;
    };
    auto resolve = Frame("resolve"); resolve.pushKV("id", 1); resolve.pushKV("domain", context.domain); service.Command(resolve);
    const auto resolved = next();
    if (!resolved || (*resolved)["type"].get_str() != "resolved" || !(*resolved)["ok"].get_bool()) throw std::runtime_error("Public DNS resolution failed");
    uint64_t sequence = 1, scheduled = 0, active = 0, completed = 0;
    std::deque<UniValue> recent;
    std::optional<UniValue> winner;
    auto last_progress = begin - std::chrono::seconds(1);
    auto progress = [&](bool force) {
        const auto now = Clock::now(); if (!force && now - last_progress < std::chrono::seconds(1)) return;
        auto output = Frame("progress"); output.pushKV("attempts", completed); output.pushKV("elapsed", std::chrono::duration<double>(now - begin).count()); output.pushKV("bestWorkHash", UniValue());
        UniValue stats(UniValue::VOBJ), samples(UniValue::VARR); for (const auto& row : recent) samples.push_back(row);
        stats.pushKV("validation", "certificate-proof-v1"); stats.pushKV("completed", completed); stats.pushKV("recent", samples); output.pushKV("attemptStats", stats);
        EmitFrame(output.write()); last_progress = now;
    };
    auto record = [&](const UniValue& frame) {
        if (!frame["validationPassed"].isBool()) return;
        ++completed; UniValue sample(UniValue::VARR); sample.push_back(frame["validationPassed"]); sample.push_back(frame["seconds"]); recent.push_back(std::move(sample));
        if (recent.size() > 100) recent.pop_front();
    };
    while (Clock::now() < deadline) {
        while (active < concurrency && scheduled < limit) {
            auto attempt = Frame("attempt"); attempt.pushKV("id", ++sequence); attempt.pushKV("context", PublicContext(context));
            attempt.pushKV("bountyId", context.txid + ":" + std::to_string(context.input_index)); attempt.pushKV("successfulConnections", "0");
            service.Command(attempt); ++scheduled; ++active;
        }
        if (!active) break;
        const auto frame = next(); if (!frame) break;
        const auto type = (*frame)["type"].get_str();
        if (type == "error") break;
        if (type != "attempt") continue;
        --active; record(*frame); progress(false);
        if ((*frame)["verified"].isTrue()) { winner = *frame; break; }
        if ((*frame).exists("blocked")) break;
    }
    service.Close();
    { std::lock_guard lock(mutex); for (const auto& frame : received) if (frame["type"].get_str() == "attempt") record(frame); }
    progress(true);
    if (!winner) throw std::runtime_error("No valid proof reached the requested target within the generation limits");
    auto result = Frame("result"); result.pushKV("verified", true); result.pushKV("proof", (*winner)["proof"]); result.pushKV("context", PublicContext(context)); result.pushKV("attempts", completed);
    EmitFrame(result.write()); return 0;
}
} // namespace
int main(int argc, char** argv) {
    // Every protocol frame is explicitly flushed by EmitFrame. Input does not
    // need to synchronize stdout again for every byte of a bounded JSON line.
    std::cin.tie(nullptr);
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY); _setmode(_fileno(stdout), _O_BINARY);
#else
    std::signal(SIGPIPE, SIG_IGN);
#endif
    try {
        std::vector<std::string> args(argv + 1, argv + argc);
        bool native_required = false, rsa_required = false;
        while (!args.empty() && (args.back() == "--require-rsa-exponent-64" || args.back() == "--require-native-mbedtls")) {
            auto& present = args.back() == "--require-native-mbedtls" ? native_required : rsa_required;
            if (present) throw std::invalid_argument("Duplicate helper requirement");
            present = true; args.pop_back();
        }
        if (args.empty()) return Generate();
        if (args.size() != 1) throw std::invalid_argument("Unknown helper arguments");
        if (args[0] == "--service") return RunService(std::cin, EmitFrame);
        if (args[0] == "--self-test") { InitializeCrypto(); EmitFrame(ReadyFrame().write()); return 0; }
        if (args[0] == "--verify-proof") return VerifyOffline();
        if (args[0] == "--probe-rsa") return Probe();
        throw std::invalid_argument("Unknown helper arguments");
    } catch (...) {
        try { auto response = Frame("error"); response.pushKV("message", "Invalid helper request or helper operation failed"); EmitFrame(response.write()); } catch (...) {}
        return 1;
    }
}
