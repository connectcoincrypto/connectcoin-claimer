// Copyright (c) 2026 The ConnectCoin developers. MIT license.
// Differential tests use the unmodified pinned Mbed TLS C implementation.
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <claimer/crypto.hpp>
#include "mbedtls_sha256.h"
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <psa/crypto.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <random>
#include <span>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

namespace {
using Hash = std::array<unsigned char, 32>;
void Require(bool value, const char* why) { if (!value) throw std::runtime_error(why); }
Hash Digest(std::span<const unsigned char> bytes, int is224, bool reference, size_t chunk = 0) {
    mbedtls_sha256_context context;
    auto init = reference ? connectcoin_sha256_reference_init : mbedtls_sha256_init;
    auto start = reference ? connectcoin_sha256_reference_starts : mbedtls_sha256_starts;
    auto update = reference ? connectcoin_sha256_reference_update : mbedtls_sha256_update;
    auto finish = reference ? connectcoin_sha256_reference_finish : mbedtls_sha256_finish;
    auto free = reference ? connectcoin_sha256_reference_free : mbedtls_sha256_free;
    init(&context); Hash result{};
    Require(start(&context, is224) == 0, "hash starts");
    Require(update(&context, nullptr, 0) == 0, "empty update");
    if (!chunk) chunk = std::max<size_t>(1, bytes.size());
    for (size_t offset = 0; offset < bytes.size(); offset += chunk)
        Require(update(&context, bytes.data() + offset, std::min(chunk, bytes.size() - offset)) == 0, "hash update");
    Require(finish(&context, result.data()) == 0, "hash finish");
    free(&context);
    const auto* erased = reinterpret_cast<const unsigned char*>(&context);
    Require(std::all_of(erased, erased + sizeof(context), [](auto c) { return c == 0; }), "context not zeroized");
    return result;
}
std::span<const unsigned char> Bytes(std::string_view value) { return {reinterpret_cast<const unsigned char*>(value.data()), value.size()}; }
void KnownVectors() {
    const std::array<std::string_view, 3> inputs{"", "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
    const char* sha256[]{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"};
    const char* sha224[]{"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"};
    for (int is224 : {0, 1}) for (size_t i = 0; i < inputs.size(); ++i) for (bool reference : {false, true}) {
        const auto result = Digest(Bytes(inputs[i]), is224, reference, 1);
        Require(claimer::Hex(std::span(result).first(is224 ? 28 : 32)) == (is224 ? sha224[i] : sha256[i]), "known SHA vector");
    }
    const std::vector<unsigned char> million(1000000, 'a');
    Require(claimer::Hex(Digest(million, 0, false, 997)) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "million-a vector");
}
void Differential() {
    std::mt19937_64 random(0x534841323536);
    std::vector<unsigned char> storage(16432);
    for (auto& value : storage) value = static_cast<unsigned char>(random());
    const std::array<size_t, 19> lengths{0,1,2,31,32,55,56,57,63,64,65,119,120,127,128,129,1024,8193,16384};
    for (int is224 : {0,1}) for (size_t offset = 0; offset < 16; ++offset) for (size_t length : lengths) {
        const auto data = std::span(storage).subspan(offset, length);
        const auto expected = Digest(data, is224, true);
        for (size_t chunk : {size_t{0}, size_t{1}, size_t{7}, size_t{63}, size_t{64}, size_t{65}, size_t{997}})
            Require(Digest(data, is224, false, chunk) == expected, "partial/multiblock/unaligned differential");
        Hash once{};
        Require(mbedtls_sha256(data.data(), data.size(), once.data(), is224) == 0 && once == expected, "one-shot differential");
    }
    for (size_t trial = 0; trial < 256; ++trial) {
        mbedtls_sha256_context actual{}, expected{};
        for (auto& word : actual.state) word = static_cast<uint32_t>(random());
        actual.total[0] = 0xfffffff0U; actual.total[1] = 9; actual.is224 = static_cast<int>(trial & 1);
        expected = actual;
        const auto* data = storage.data() + trial % 16;
        Require(connectcoin_sha256_portable_process(&expected, data) == 0, "reference compression");
        Require(mbedtls_internal_sha256_process(&actual, data) == 0, "dispatched compression");
        Require(std::memcmp(&actual, &expected, sizeof(actual)) == 0, "compression modifies only state");
    }
    for (int is224 : {0,1}) {
        mbedtls_sha256_context a{}, b{}, expected{};
        mbedtls_sha256_init(&a); mbedtls_sha256_init(&b); connectcoin_sha256_reference_init(&expected);
        Require(mbedtls_sha256_starts(&a, is224) == 0 && connectcoin_sha256_reference_starts(&expected, is224) == 0, "clone starts");
        Require(mbedtls_sha256_update(&a, storage.data(), 63) == 0 && connectcoin_sha256_reference_update(&expected, storage.data(), 63) == 0, "clone prefix");
        // Simulate byte-counter carry without allocating four GiB.
        a.total[0] = expected.total[0] = 0xffffffffU; a.total[1] = expected.total[1] = 7;
        mbedtls_sha256_clone(&b, &a);
        Require(mbedtls_sha256_update(&b, storage.data()+1, 129) == 0 && connectcoin_sha256_reference_update(&expected, storage.data()+1, 129) == 0, "carry update");
        Hash left{}, right{};
        Require(mbedtls_sha256_finish(&b, left.data()) == 0 && connectcoin_sha256_reference_finish(&expected, right.data()) == 0 && left == right, "clone/carry differential");
        mbedtls_sha256_free(&a); mbedtls_sha256_free(&b); connectcoin_sha256_reference_free(&expected);
    }
    mbedtls_sha256_context invalid{};
    mbedtls_sha256_init(&invalid);
    for (int mode : {-1,2,255}) Require(mbedtls_sha256_starts(&invalid, mode) == connectcoin_sha256_reference_starts(&invalid, mode) &&
        mbedtls_sha256_starts(&invalid, mode) == MBEDTLS_ERR_SHA256_BAD_INPUT_DATA, "invalid hash mode changed");
    mbedtls_sha256_free(&invalid); mbedtls_sha256_free(nullptr);
}
void PublicApis() {
    // RFC 5869 test case 1 exercises HMAC/HKDF through the same SHA compressor.
    const auto ikm = claimer::Unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const auto salt = claimer::Unhex("000102030405060708090a0b0c");
    const auto info = claimer::Unhex("f0f1f2f3f4f5f6f7f8f9");
    std::array<unsigned char,42> output{};
    Require(mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt.data(), salt.size(), ikm.data(), ikm.size(), info.data(), info.size(), output.data(), output.size()) == 0, "HKDF call");
    Require(claimer::Hex(output) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "HKDF RFC vector");
    for (auto algorithm : {PSA_ALG_SHA_224, PSA_ALG_SHA_256}) {
        Hash result{}; size_t length{};
        Require(psa_hash_compute(algorithm, reinterpret_cast<const unsigned char*>("abc"), 3, result.data(), result.size(), &length) == PSA_SUCCESS, "PSA hash");
        const auto reference = Digest(Bytes("abc"), algorithm == PSA_ALG_SHA_224, true);
        Require(length == (algorithm == PSA_ALG_SHA_224 ? 28 : 32) && std::equal(result.begin(), result.begin() + length, reference.begin()), "PSA/reference differential");
        psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
        Require(psa_hash_setup(&operation, algorithm) == PSA_SUCCESS && psa_hash_update(&operation, reinterpret_cast<const unsigned char*>("a"), 1) == PSA_SUCCESS &&
            psa_hash_update(&operation, reinterpret_cast<const unsigned char*>("bc"), 2) == PSA_SUCCESS, "PSA multipart");
        Require(psa_hash_finish(&operation, result.data(), result.size(), &length) == PSA_SUCCESS && std::equal(result.begin(), result.begin() + length, reference.begin()), "PSA multipart differential");
        Require(psa_hash_abort(&operation) == PSA_SUCCESS, "PSA abort cleanup");
    }
    Hash short_output{}; size_t written = 42;
    // Pinned Mbed TLS 3.6.7 reports hash_size and poisons exactly that many
    // bytes on this error (psa_crypto_hash.c), including in a stock OFF build.
    Require(psa_hash_compute(PSA_ALG_SHA_256, reinterpret_cast<const unsigned char*>("abc"), 3, short_output.data(), 31, &written) == PSA_ERROR_BUFFER_TOO_SMALL && written == 31 &&
        std::all_of(short_output.begin(), short_output.begin() + 31, [](unsigned char byte) { return byte == '!'; }) && short_output[31] == 0, "PSA output-size rejection");
}
void Threads() {
    std::atomic<bool> okay{true};
    std::vector<std::thread> threads;
    for (int i=0; i<12; ++i) threads.emplace_back([&, i] {
        try {
#if defined(CONNECTCOIN_SHA256_TESTING)
            connectcoin_sha256_test_force_portable(i & 1);
#endif
            for (int j=0; j<128; ++j) Require(Digest(Bytes("concurrent independent SHA state"), j&1, false) == Digest(Bytes("concurrent independent SHA state"), j&1, true), "concurrent differential");
        } catch (...) { okay = false; }
    });
    for (auto& thread : threads) thread.join();
    Require(okay, "concurrent dispatch/state");
}
void Routing() {
#if defined(CONNECTCOIN_SHA256_TESTING)
    const auto hardware = connectcoin_sha256_test_hardware_calls(), portable = connectcoin_sha256_test_portable_calls();
    (void)Digest(Bytes("abc"), 0, false);
    Require(connectcoin_sha256_test_hardware_calls() == hardware + (connectcoin_sha256_hardware_available() ? 1 : 0) &&
        connectcoin_sha256_test_portable_calls() == portable + (connectcoin_sha256_hardware_available() ? 0 : 1), "automatic route not used");
    connectcoin_sha256_test_force_portable(1);
    const auto before = connectcoin_sha256_test_hardware_calls(), fallback = connectcoin_sha256_test_portable_calls();
    KnownVectors(); Differential(); PublicApis();
    Require(connectcoin_sha256_test_hardware_calls() == before && connectcoin_sha256_test_portable_calls() > fallback, "forced portable not used");
    connectcoin_sha256_test_force_portable(0);
#endif
}
void Benchmark() {
    std::vector<unsigned char> input(4096, 0x5a);
    constexpr size_t iterations = 8192;
    for (bool reference : {true, false}) {
        unsigned checksum = 0;
        const auto start = std::chrono::steady_clock::now();
        for (size_t i=0; i<iterations; ++i) {
            input[0] = static_cast<unsigned char>(i);
            Hash output{};
            const auto hash = reference ? connectcoin_sha256_reference : mbedtls_sha256;
            Require(hash(input.data(), input.size(), output.data(), 0) == 0, "benchmark hash");
            checksum += output[i % output.size()];
        }
        const auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
        std::cout << (reference ? "portable_reference" : "automatic_dispatch") << " SHA256_4KiB MiB/s=" << (input.size()*iterations/1048576.0)/seconds << " checksum=" << checksum << '\n';
    }
}
}
int main(int argc, char** argv) {
    try {
        // Exercise thread-safe first-use dispatch before crypto initialization.
        Threads(); claimer::InitializeCrypto();
        KnownVectors(); Differential(); PublicApis(); Routing();
        std::cout << "SHA-224/256 vectors, differential, partial/unaligned, clone/carry, PSA/HKDF, zeroization and threads passed; hardware=";
#if defined(CONNECTCOIN_SHA256_ACCELERATION)
        std::cout << connectcoin_sha256_hardware_available();
#else
        std::cout << "disabled";
#endif
        std::cout << '\n';
        if (argc == 2 && std::string_view(argv[1]) == "--benchmark") Benchmark();
        else Require(argc == 1, "unknown SHA test argument");
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
