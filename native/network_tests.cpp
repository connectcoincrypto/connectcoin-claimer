// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#include <claimer/network.hpp>
#include "p2c_tls_private.h"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <cerrno>
#include <sys/socket.h>
#endif
#include <chrono>
#include <future>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <type_traits>

namespace {
static_assert(!std::is_default_constructible_v<claimer::CapturedProof>);
static_assert(std::is_copy_constructible_v<claimer::CapturedProof>);
static_assert(std::is_move_constructible_v<claimer::CapturedProof>);
void Require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}
claimer::Context FixtureContext()
{
    return {"example.com", std::string(64, '1'), 0, std::string(64, 'f'), 1, 7, 1800000000};
}
void RequireTlsReused(const claimer::TlsReuseSnapshot& before)
{
    const auto after = claimer::TlsReuseSnapshotForTesting();
    Require(after.idle_clean, "TLS context retained prior session, secrets or callbacks");
    Require(after.discarded == before.discarded, "Healthy TLS storage was discarded");
    Require(after.resets == before.resets + 1, "Capture did not fully reset TLS on exit");
    Require(after.setups == before.setups + (before.input_buffer == 0 ? 1 : 0), "Capture repeated TLS setup");
    Require(after.input_buffer != 0 && after.output_buffer != 0, "TLS buffers were not retained");
    if (before.input_buffer != 0) {
        Require(after.input_buffer == before.input_buffer && after.output_buffer == before.output_buffer,
                "TLS capture replaced reusable buffers");
    }
}
void SocketFailureTests()
{
    const auto classified = [](int error, bool creating, int expected) {
        // -1 means an ordinary error, 0 endpoint-only, 1 unsupported family.
        int actual{-2};
        try { claimer::ThrowSocketFailureForTesting(error, creating); }
        catch (const claimer::LocalEndpointUnavailable& failure) { actual = failure.family_unsupported ? 1 : 0; }
        catch (const std::runtime_error&) { actual = -1; }
        Require(actual == expected, "Socket error classified at wrong endpoint/family scope");
    };
#ifdef _WIN32
    const std::vector<int> unsupported{WSAEAFNOSUPPORT, WSAEPFNOSUPPORT, WSAEPROTONOSUPPORT, WSAESOCKTNOSUPPORT};
    const std::vector<int> route{WSAENETUNREACH, WSAEHOSTUNREACH, WSAENETDOWN};
    const std::vector<int> ordinary{0, WSAECONNREFUSED, WSAECONNRESET, WSAETIMEDOUT, WSAEMFILE, WSAENOBUFS,
                                   WSAEACCES, WSAEINVAL, WSAEINTR, WSAEWOULDBLOCK, WSAEINPROGRESS, WSAEALREADY,
                                   WSAEPROTOTYPE, WSAEADDRINUSE, WSAEADDRNOTAVAIL, WSAENOTSOCK};
#else
    const std::vector<int> unsupported{EAFNOSUPPORT, EPROTONOSUPPORT,
#ifdef EPFNOSUPPORT
                                       EPFNOSUPPORT,
#endif
#ifdef ESOCKTNOSUPPORT
                                       ESOCKTNOSUPPORT,
#endif
    };
    const std::vector<int> route{ENETUNREACH, EHOSTUNREACH, ENETDOWN};
    const std::vector<int> ordinary{0, ECONNREFUSED, ECONNRESET, ETIMEDOUT, EMFILE, ENFILE, ENOBUFS, ENOMEM,
                                   EACCES, EPERM, EINVAL, EINTR, EAGAIN, EWOULDBLOCK, EINPROGRESS, EALREADY,
                                   EPROTOTYPE, EADDRINUSE, EADDRNOTAVAIL, ENOTSOCK};
#endif
    for (int error : unsupported) {
        classified(error, true, 1);
        classified(error, false, -1); // A connect error is not socket-family proof.
    }
    for (int error : route) {
        classified(error, false, 0);
        classified(error, true, -1); // Route scope only comes from connect/SO_ERROR.
    }
    for (int error : ordinary) {
        classified(error, true, -1);
        classified(error, false, -1);
    }
}
void PolicyTests()
{
    SocketFailureTests();
    Require(claimer::SocketFlagsForTesting(false) && claimer::SocketFlagsForTesting(true), "Capture socket flags missing");
    for (const char* ip : {"8.8.8.8", "1.1.1.1", "9.9.9.9", "192.0.0.9", "192.0.0.10", "192.0.1.1",
                          "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0",
                          "2001:4860:4860::8888", "2606:4700:4700::1111", "2001:1::1", "2001:1::2",
                          "2001:3::1", "2001:4:112::1", "2001:20::1", "2001:30::1"})
        if (!claimer::IsPublicIp(ip)) throw std::runtime_error(std::string("Public endpoint incorrectly rejected: ") + ip);
    for (const char* ip : {"", "localhost", "1.2.3", "1.2.3.256", "01.2.3.4", "1.02.3.4", "1.2.03.4", "1.2.3.04",
                          "008.008.008.008", "8.8.8.8.", " 8.8.8.8", "8.8.8.8 ", "0x8.8.8.8", "0.0.0.0", "0.255.255.255",
                          "10.0.0.1", "100.64.0.0", "100.127.255.255", "127.0.0.1", "169.254.169.254",
                          "172.16.0.0", "172.31.255.255", "192.0.0.1", "192.0.0.170", "192.0.2.1", "192.168.1.1",
                          "198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1",
                          "255.255.255.255", "::", "::1", "::ffff:8.8.8.8", "64:ff9b::808:808", "64:ff9b:1::1",
                          "100::1", "2001::1", "2001:2::1", "2001:db8::1", "2002:808:808::1", "3fff::1",
                          "fc00::1", "fe80::1", "fec0::1", "ff02::1", "2001:4860::1%1"})
        if (claimer::IsPublicIp(ip)) throw std::runtime_error(std::string("Nonpublic or noncanonical endpoint accepted: ") + ip);
    const std::string embedded("8.8.8.8\0garbage", 15);
    Require(!claimer::IsPublicIp(embedded), "Embedded NUL accepted");
    auto context = FixtureContext();
    claimer::CaptureControl control;
    bool started{};
    try { claimer::Capture(context, {"127.0.0.1", AF_INET, 443}, control, [&] { started = true; }); }
    catch (const std::runtime_error&) {}
    Require(!started, "Production capture invoked start for private address");
    control.Cancel();
    bool cancelled{};
    try { claimer::Capture(context, {"8.8.8.8", AF_INET, 443}, control, [&] { started = true; }); }
    catch (const claimer::CaptureCancelled&) { cancelled = true; }
    Require(cancelled && !started, "Pre-cancelled capture reached start");
    claimer::CaptureControl concurrent;
    std::thread first([&] { concurrent.Cancel(); });
    std::thread second([&] { concurrent.Cancel(); });
    first.join(); second.join();
    Require(concurrent.Cancelled(), "Concurrent cancellation flag lost");
}
}

int main(int argc, char** argv)
{
    try {
        if (argc == 1) { PolicyTests(); std::cout << "network policy/cancellation tests passed\n"; return 0; }
        if (argc == 4 && std::string(argv[1]) == "certificate-message") {
            std::ifstream file(argv[2], std::ios::binary);
            const claimer::Bytes message{std::istreambuf_iterator<char>(file), {}};
            Require(file.good() || file.eof(), "Cannot read certificate fixture");
            Require(message.size() >= 4 && message.size() <= 65540, "Certificate fixture size invalid");
            const auto mask = std::stoull(argv[3]);
            Require(mask <= 0xffffffff, "Invalid sent extension mask");
            claimer::InitializeCrypto();
            for (int abbreviated : {0, 1}) {
                uint32_t received{};
                int peer{};
                const int status = connectcoin_p2c_test_certificate(message.data(), message.size(),
                    abbreviated, static_cast<uint32_t>(mask), &received, &peer);
                bool der_ok = status == 0;
                if (der_ok) {
                    try { claimer::ValidateCertificateMessage(message); }
                    catch (const std::exception&) { der_ok = false; }
                }
                std::cout << status << ' ' << der_ok << ' ' << received << ' ' << peer << '\n';
            }
            return 0;
        }
        // This entire executable links only the test-only loopback network
        // library. It is not shipped or reachable through production CLI.
        if (argc != 4 && argc != 5) throw std::runtime_error("fixture usage: <mode> <loopback-port> <timeout-ms> [test-root.pem]");
        const std::string mode(argv[1]);
        const int port = std::stoi(argv[2]), timeout_ms = std::stoi(argv[3]);
        if (port < 1 || port > 65535 || timeout_ms < 1 || timeout_ms > 10000) throw std::runtime_error("Invalid fixture parameters");
        claimer::CaptureControl control;
        auto context = FixtureContext();
        if (mode.starts_with("capture-mask-")) {
            const auto mask = std::stoul(mode.substr(13));
            Require(mask >= 1 && mask <= 7, "Invalid fixture signature mask");
            context.signature_algorithms_mask = static_cast<uint8_t>(mask);
        }
        std::string roots;
        if (argc == 5) {
            std::ifstream file(argv[4], std::ios::binary);
            roots.assign(std::istreambuf_iterator<char>(file), {});
            Require(!roots.empty() && roots.size() <= 1024 * 1024, "Invalid fixture root file");
        }
        auto authenticate = [&](const claimer::Bytes& proof) {
            if (roots.empty()) return;
            const std::span<const unsigned char> root_bytes{reinterpret_cast<const unsigned char*>(roots.data()), roots.size()};
            const auto good = claimer::VerifyProofForTesting(proof, context, root_bytes);
            Require(good.meets_target, "Fixture work target mismatch");
            // Own bytes/context, then destroy/mutate all caller inputs. Copies
            // and moves must keep every parsed span bound to the owned bytes.
            auto owned = [&] {
                auto caller_bytes = proof;
                auto caller_context = context;
                const claimer::PreparedContext prepared(caller_context);
                const claimer::CapturedProof original(caller_bytes, prepared);
                auto copy = original;
                caller_bytes.assign(1, 0);
                caller_context.domain = "invalid";
                caller_context.validation_time = 1;
                auto moved = std::move(copy);
                bool moved_from_rejected{};
                try { (void)copy.Encoded(); } catch (const std::exception&) { moved_from_rejected = true; }
                Require(moved_from_rejected, "Moved-from captured proof remained usable");
                return moved;
            }();
            const auto owned_result = claimer::VerifyCapturedForTesting(owned, root_bytes);
            Require(owned.Encoded() == proof && owned_result.work_hash == good.work_hash &&
                    owned_result.signature_scheme == good.signature_scheme, "Owned proof changed after caller destruction");
            auto cross_thread = std::async(std::launch::async, [owned, roots] {
                const std::span<const unsigned char> bytes{reinterpret_cast<const unsigned char*>(roots.data()), roots.size()};
                return claimer::VerifyCapturedForTesting(owned, bytes);
            });
            Require(cross_thread.get().work_hash == good.work_hash, "Owned proof failed cross-thread verification");
            auto invalid_owned = proof; invalid_owned.back() ^= 1;
            const claimer::CapturedProof altered(invalid_owned, claimer::PreparedContext(context));
            bool invalid_owned_rejected{};
            try { claimer::VerifyCapturedForTesting(altered, root_bytes); } catch (const std::exception&) { invalid_owned_rejected = true; }
            Require(invalid_owned_rejected, "Owned proof skipped dynamic CV verification");
            auto reject_context = [&](const claimer::Context& changed) {
                bool failed{};
                try { claimer::VerifyProofForTesting(proof, changed, root_bytes); }
                catch (const std::exception&) { failed = true; }
                Require(failed, "Verifier reused validity across changed context");
            };
            auto changed = context;
            changed.validation_time = 1; reject_context(changed);
            changed.validation_time = 253402300799; reject_context(changed);
            changed = context; changed.signature_algorithms_mask = good.signature_scheme == 0x0403 ? 2 : 1;
            reject_context(changed);
            changed = context; ++changed.input_index; reject_context(changed);
            changed = context; changed.connection_work_target = std::string(64, '0');
            Require(!claimer::VerifyProofForTesting(proof, changed, root_bytes).meets_target,
                    "Valid below-target outcome incorrectly treated as winner");
            auto bad = proof; bad.back() ^= 1;
            bool rejected{};
            try { claimer::VerifyProofForTesting(bad, context, root_bytes); }
            catch (const std::exception&) { rejected = true; }
            Require(rejected, "Tampered CV signature accepted");
            Require(claimer::ParseProof(bad, context).connection_work_hash == claimer::ParseProof(proof, context).connection_work_hash,
                    "CV unexpectedly contributes to connection work");
            rejected = false;
            try { claimer::VerifyProof(proof, context); }
            catch (const std::exception&) { rejected = true; }
            Require(rejected, "Production verifier accepted fixture root");
            bad = proof; bad.pop_back(); rejected = false;
            try { claimer::VerifyProofForTesting(bad, context, root_bytes); }
            catch (const std::exception&) { rejected = true; }
            Require(rejected, "Truncated proof accepted");
        };
        if (mode.starts_with("reuse-sequence-")) {
            const auto compatible_mask = static_cast<uint8_t>(std::stoul(mode.substr(15)));
            Require(compatible_mask == 1 || compatible_mask == 2, "Invalid reuse fixture mask");
            Require(!roots.empty(), "Reuse fixtures must authenticate every successful proof");
            for (int index = 0; index < 7; ++index) {
                context = FixtureContext();
                context.input_index = static_cast<uint32_t>(index);
                if (index == 2 || index == 4) context.domain = "alternate.example.com";
                context.signature_algorithms_mask = (index == 2 || index == 4) ? compatible_mask : 7;
                const auto before = claimer::TlsReuseSnapshotForTesting();
                Require(before.idle_clean, "Worker TLS was dirty before capture");
                if (index == 4) claimer::FailNextTlsResetForTesting();
                claimer::CaptureControl own_control;
                if (index == 3) claimer::OnTlsClientHelloForTesting([&] { own_control.Cancel(); });
                if (index == 5) claimer::OnTlsClientHelloForTesting([] {
                    // Expire only after the complete ClientHello is captured,
                    // so slow/oversubscribed hosts still exercise its fresh key
                    // share and the partial-handshake reset after a timeout.
                    std::this_thread::sleep_for(std::chrono::milliseconds{2050});
                });
                bool failed{}, cancelled{}, timed_out{};
                try {
                    const auto captured = claimer::CapturePreparedForTesting(claimer::PreparedContext(context),
                        {"127.0.0.1", AF_INET, static_cast<uint16_t>(port)}, own_control,
                        {},
                        std::chrono::milliseconds{index == 5 ? 2000 : timeout_ms}, index == 2 || index == 6);
                    authenticate(captured.Encoded());
                    std::cout << index << ' ' << claimer::Hex(captured.Encoded()) << '\n';
                } catch (const claimer::CaptureCancelled&) { cancelled = true; }
                catch (const claimer::CaptureTimeout&) { timed_out = true; }
                catch (const std::runtime_error&) {
                    if (index != 1) throw;
                    failed = true;
                }
                Require(failed == (index == 1) && cancelled == (index == 3) && timed_out == (index == 5),
                        "Reuse sequence changed error/cancellation/deadline behavior");
                if (index == 4) {
                    const auto after = claimer::TlsReuseSnapshotForTesting();
                    Require(after.idle_clean && after.discarded == before.discarded + 1 &&
                            after.input_buffer == 0 && after.output_buffer == 0,
                            "Failed reset retained an uncertain TLS context");
                } else RequireTlsReused(before);
            }
            return 0;
        }
        if (mode == "repeat") {
            claimer::ClearCertificateCacheForTesting();
            for (int index = 0; index < 2; ++index) {
                const auto before = claimer::TlsReuseSnapshotForTesting();
                claimer::CaptureControl own_control;
                const auto captured = claimer::CapturePreparedForTesting(claimer::PreparedContext(context),
                    {"127.0.0.1", AF_INET, static_cast<uint16_t>(port)}, own_control, {},
                    std::chrono::milliseconds{timeout_ms});
                RequireTlsReused(before);
                authenticate(captured.Encoded());
                std::cout << claimer::Hex(captured.Encoded()) << '\n';
            }
            const auto stats = claimer::CertificateCacheStatsForTesting();
            Require(stats.misses == 1 && stats.metadata_builds == 1 && stats.hits >= 1,
                    "Repeated exact certificate was reparsed by the owned cache");
            return 0;
        }
        if (mode == "parallel") {
            std::vector<std::future<std::vector<claimer::Bytes>>> jobs;
            for (int index = 0; index < 8; ++index) jobs.push_back(std::async(std::launch::async, [&] {
                std::vector<claimer::Bytes> proofs;
                for (int repeat = 0; repeat < 2; ++repeat) {
                    const auto before = claimer::TlsReuseSnapshotForTesting();
                    claimer::CaptureControl own_control;
                    const auto captured = claimer::CapturePreparedForTesting(claimer::PreparedContext(context), {"127.0.0.1", AF_INET, static_cast<uint16_t>(port)},
                        own_control, {}, std::chrono::milliseconds{timeout_ms});
                    RequireTlsReused(before);
                    authenticate(captured.Encoded());
                    proofs.push_back(captured.Encoded());
                }
                return proofs;
            }));
            for (auto& job : jobs) for (const auto& proof : job.get()) std::cout << claimer::Hex(proof) << '\n';
            return 0;
        }
        int starts{};
        bool cancelled{};
        std::promise<void> start_gate;
        std::future<void> cancellation;
        if (mode == "cancel" || mode == "cancel-start") {
            cancellation = std::async(std::launch::async, [&] {
                if (start_gate.get_future().wait_for(std::chrono::seconds{2}) != std::future_status::ready) return;
                std::this_thread::sleep_for(std::chrono::milliseconds{40});
                control.Cancel();
            });
        }
        const auto begin = std::chrono::steady_clock::now();
        auto on_started = [&] {
            ++starts;
            if (mode == "cancel" || mode == "cancel-start") start_gate.set_value();
            if (mode == "cancel-start") {
                while (!control.Cancelled()) std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
            if (mode == "slow-start") std::this_thread::sleep_for(std::chrono::milliseconds{timeout_ms + 50});
            if (mode == "reject-start") throw std::runtime_error("fixture start rejected");
        };
        try {
            const auto captured = claimer::CapturePreparedForTesting(claimer::PreparedContext(context), {"127.0.0.1", AF_INET, static_cast<uint16_t>(port)},
                control, on_started, std::chrono::milliseconds{timeout_ms}, mode == "complete");
            const auto& proof = captured.Encoded();
            const auto parsed = claimer::ParseProof(proof, context);
            Require(parsed.certificate_verify.size() >= 8, "Captured CV missing");
            Require(starts == 1, "Capture start count mismatch");
            authenticate(proof);
            std::cout << claimer::Hex(proof) << '\n';
        } catch (const claimer::CaptureCancelled&) {
            cancelled = true;
            if (mode != "cancel" && mode != "cancel-start") throw;
            Require(starts == 1, "Cancelled capture start count mismatch");
            const auto elapsed = std::chrono::steady_clock::now() - begin;
            Require(elapsed < std::chrono::seconds{2}, "Cancellation exceeded bound");
            std::cout << "cancelled\n";
        }
        if (cancellation.valid()) cancellation.get();
        if (mode == "cancel" || mode == "cancel-start") Require(cancelled, "Cancellation did not stop capture");
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
