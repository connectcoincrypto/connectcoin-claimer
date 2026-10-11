// Copyright (c) 2026 The ConnectCoin developers. MIT license.
// Only the compression primitive changes. Provider init/update/finish retain
// their original buffering, length accounting, SHA-224 support and zeroization.
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls_sha256.h"
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER != 0x03060700
#error "Review SHA-256 dispatch before changing pinned Mbed TLS"
#endif
#if defined(CONNECTCOIN_SHA256_X86_BACKEND)
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
extern "C" void connectcoin_sha256_shani(uint32_t*, const unsigned char*);
#endif
#if defined(CONNECTCOIN_SHA256_TESTING)
#include <atomic>
static std::atomic<uint64_t> hardware_calls{}, portable_calls{};
static thread_local bool force_portable{};
extern "C" uint64_t connectcoin_sha256_test_hardware_calls(void) { return hardware_calls.load(std::memory_order_relaxed); }
extern "C" uint64_t connectcoin_sha256_test_portable_calls(void) { return portable_calls.load(std::memory_order_relaxed); }
extern "C" void connectcoin_sha256_test_force_portable(int value) { force_portable = value != 0; }
#endif

namespace {
bool DetectHardware() noexcept {
#if defined(CONNECTCOIN_SHA256_X86_BACKEND)
    // Backend uses legacy XMM SHA, SSSE3 shuffle/align and SSE4.1 blend; never
    // AVX/YMM. x86-64 OSes guarantee XMM state preservation. 32-bit/non-x86
    // builds deliberately use the stock portable fallback.
    unsigned ecx1{}, ebx7{};
#if defined(_MSC_VER)
    int registers[4]{};
    __cpuidex(registers, 0, 0);
    if (registers[0] < 7) return false;
    __cpuidex(registers, 1, 0); ecx1 = static_cast<unsigned>(registers[2]);
    __cpuidex(registers, 7, 0); ebx7 = static_cast<unsigned>(registers[1]);
#else
    if (__get_cpuid_max(0, nullptr) < 7) return false;
    unsigned eax{}, ebx{}, ecx{}, edx{};
    __cpuid_count(1, 0, eax, ebx, ecx, edx); ecx1 = ecx;
    __cpuid_count(7, 0, eax, ebx, ecx, edx); ebx7 = ebx;
#endif
    return (ecx1 & (1U << 9)) && (ecx1 & (1U << 19)) && (ebx7 & (1U << 29));
#else
    return false;
#endif
}
}
extern "C" int connectcoin_sha256_hardware_available(void) {
    // C++ local-static initialization is thread-safe; CPUID executes once.
    static const bool available = DetectHardware();
    return available;
}
extern "C" int mbedtls_internal_sha256_process(mbedtls_sha256_context* context, const unsigned char data[64]) {
#if defined(CONNECTCOIN_SHA256_X86_BACKEND)
    if (connectcoin_sha256_hardware_available()
#if defined(CONNECTCOIN_SHA256_TESTING)
        && !force_portable
#endif
    ) {
        connectcoin_sha256_shani(context->state, data);
#if defined(CONNECTCOIN_SHA256_TESTING)
        hardware_calls.fetch_add(1, std::memory_order_relaxed);
#endif
        return 0;
    }
#endif
#if defined(CONNECTCOIN_SHA256_TESTING)
    portable_calls.fetch_add(1, std::memory_order_relaxed);
#endif
    return connectcoin_sha256_portable_process(context, data);
}
