// Copyright (c) 2026 The ConnectCoin developers. MIT license.
// RFC 7748 vectors: https://www.rfc-editor.org/rfc/rfc7748.html#section-5.2
// and https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1.
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <claimer/crypto.hpp>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <psa/crypto.h>
#if defined(CONNECTCOIN_X25519_ACCELERATION)
#include "mbedtls_x25519.h"
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <random>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {
using Bytes = std::array<unsigned char, 32>;

void Require(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

Bytes Hex(std::string_view text) {
    Require(text.size() == 64, "test vector length");
    Bytes result{};
    auto nibble = [](char c) -> unsigned char {
        if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
        throw std::runtime_error("test vector hex");
    };
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<unsigned char>((nibble(text[2 * i]) << 4) | nibble(text[2 * i + 1]));
    return result;
}

Bytes BasePoint() { Bytes value{}; value[0] = 9; return value; }
Bytes SmallPoint(unsigned char value) { Bytes result{}; result[0] = value; return result; }

// Deterministic test data and blinding randomness only; never used by production.
Bytes Next(std::mt19937_64& random) {
    Bytes result{};
    for (std::size_t i = 0; i < result.size(); i += 8) {
        const auto word = random();
        for (std::size_t j = 0; j < 8; ++j) result[i + j] = static_cast<unsigned char>(word >> (8 * j));
    }
    return result;
}

int TestRandom(void* state, unsigned char* output, std::size_t size) {
    auto& random = *static_cast<std::mt19937_64*>(state);
    for (std::size_t i = 0; i < size; ++i) output[i] = static_cast<unsigned char>(random());
    return 0;
}

struct GenericKey {
    mbedtls_ecp_keypair value;
    GenericKey() { mbedtls_ecp_keypair_init(&value); }
    ~GenericKey() { mbedtls_ecp_keypair_free(&value); }
};
struct GenericPoint {
    mbedtls_ecp_point value;
    GenericPoint() { mbedtls_ecp_point_init(&value); }
    ~GenericPoint() { mbedtls_ecp_point_free(&value); }
};
struct GenericInteger {
    mbedtls_mpi value;
    GenericInteger() { mbedtls_mpi_init(&value); }
    ~GenericInteger() { mbedtls_mpi_free(&value); }
};

struct GenericResult { int status{}; Bytes output{}; };

// The reference deliberately calls generic ECP/ECDH directly, never the PSA
// adapter or HACL. Its input decoding, clamping and rejection rules are the
// original pinned Mbed TLS implementation.
GenericResult Generic(const Bytes& scalar, const Bytes& point) {
    GenericKey key;
    GenericPoint peer;
    GenericInteger secret;
    GenericResult result;
    std::mt19937_64 random(0x5245464552454e43ULL);
    result.status = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_CURVE25519, &key.value, scalar.data(), scalar.size());
    if (!result.status) result.status = mbedtls_ecp_point_read_binary(&key.value.grp, &peer.value, point.data(), point.size());
    if (!result.status) result.status = mbedtls_ecp_check_pubkey(&key.value.grp, &peer.value);
    if (!result.status) result.status = mbedtls_ecdh_compute_shared(&key.value.grp, &secret.value, &peer.value,
                                                                  &key.value.d, TestRandom, &random);
    if (!result.status) result.status = mbedtls_mpi_write_binary_le(&secret.value, result.output.data(), result.output.size());
    return result;
}

psa_key_attributes_t Attributes(psa_ecc_family_t family = PSA_ECC_FAMILY_MONTGOMERY, std::size_t bits = 255) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
    psa_set_key_bits(&attributes, bits);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    return attributes;
}

struct PsaKey {
    mbedtls_svc_key_id_t value{};
    PsaKey() = default;
    PsaKey(const PsaKey&) = delete;
    PsaKey& operator=(const PsaKey&) = delete;
    ~PsaKey() { (void)psa_destroy_key(value); }
    void Import(const Bytes& scalar) {
        auto attributes = Attributes();
        Require(psa_import_key(&attributes, scalar.data(), scalar.size(), &value) == PSA_SUCCESS, "PSA X25519 import");
    }
    void Generate() {
        auto attributes = Attributes();
        Require(psa_generate_key(&attributes, &value) == PSA_SUCCESS, "PSA X25519 fresh key generation");
    }
};

std::uint64_t FastCalls() {
#if defined(CONNECTCOIN_X25519_ACCELERATION) && defined(CONNECTCOIN_X25519_TESTING)
    return connectcoin_mbedtls_x25519_test_calls();
#else
    return 0;
#endif
}

void RequireFastCalls(std::uint64_t before, std::uint64_t increment, std::string_view message) {
#if defined(CONNECTCOIN_X25519_ACCELERATION) && defined(CONNECTCOIN_X25519_TESTING)
    Require(FastCalls() == before + increment, message);
#else
    (void)before; (void)increment; (void)message;
#endif
}

Bytes Public(const PsaKey& key) {
    Bytes output{};
    std::size_t size = 0;
    const auto before = FastCalls();
    Require(psa_export_public_key(key.value, output.data(), output.size(), &size) == PSA_SUCCESS, "PSA public key export");
    Require(size == output.size(), "PSA public key length");
    RequireFastCalls(before, 1, "PSA public key bypassed X25519 acceleration");
    return output;
}

struct PsaResult { psa_status_t status{}; Bytes output{}; std::size_t size{}; };
PsaResult Agreement(const PsaKey& key, std::span<const unsigned char> point) {
    PsaResult result;
    result.output.fill(0xa5);
    const auto before = FastCalls();
    result.status = psa_raw_key_agreement(PSA_ALG_ECDH, key.value, point.data(), point.size(),
                                         result.output.data(), result.output.size(), &result.size);
    if (result.status == PSA_SUCCESS) {
        Require(result.size == result.output.size(), "PSA shared secret length");
        RequireFastCalls(before, 1, "PSA shared secret bypassed X25519 acceleration");
    }
    return result;
}

Bytes CheckedAgreement(const Bytes& scalar, const Bytes& point) {
    PsaKey key; key.Import(scalar);
    const auto result = Agreement(key, point);
    Require(result.status == PSA_SUCCESS, "PSA valid agreement rejected");
    return result.output;
}

void CheckEquivalent(const Bytes& scalar, const Bytes& point) {
    const auto original_scalar = scalar, original_point = point;
    const auto before = FastCalls();
    const auto reference = Generic(scalar, point);
    RequireFastCalls(before, 0, "generic ECP reference accidentally uses optimized adapter");
    PsaKey key; key.Import(scalar);
    const auto actual = Agreement(key, point);
    Require((reference.status == 0) == (actual.status == PSA_SUCCESS), "generic/PSA X25519 acceptance mismatch");
    if (!reference.status) Require(reference.output == actual.output, "generic/PSA X25519 secret mismatch");
#if defined(CONNECTCOIN_X25519_ACCELERATION)
    Bytes raw{};
    const auto raw_status = connectcoin_mbedtls_x25519_mul(raw.data(), scalar.data(), point.data());
    Require((reference.status == 0) == (raw_status == 0), "generic/raw X25519 acceptance mismatch");
    if (!reference.status) Require(raw == reference.output, "generic/raw X25519 secret mismatch");
    else Require(raw == Bytes{}, "raw X25519 failure leaked a nonzero output");
#endif
    Require(scalar == original_scalar && point == original_point, "X25519 modified caller inputs");
}

void RfcVectors() {
    const std::array<std::array<std::string_view, 3>, 2> vectors{{
        {{"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
          "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
          "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"}},
        {{"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
          "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
          "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"}}
    }};
    for (const auto& vector : vectors) {
        const auto scalar = Hex(vector[0]), point = Hex(vector[1]), expected = Hex(vector[2]);
        Require(CheckedAgreement(scalar, point) == expected, "RFC 7748 X25519 vector");
        const auto reference = Generic(scalar, point);
        Require(!reference.status && reference.output == expected, "RFC 7748 generic reference vector");
        CheckEquivalent(scalar, point);
    }
    const auto alice = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const auto bob = Hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const auto alice_public = Hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const auto bob_public = Hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const auto secret = Hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    PsaKey alice_key; alice_key.Import(alice);
    PsaKey bob_key; bob_key.Import(bob);
    Require(Public(alice_key) == alice_public && Public(bob_key) == bob_public, "RFC 7748 public keys");
    Require(CheckedAgreement(alice, bob_public) == secret && CheckedAgreement(bob, alice_public) == secret,
            "RFC 7748 bilateral shared secret");

    Bytes scalar = BasePoint(), point = scalar;
    for (int i = 0; i < 1000; ++i) {
        const auto previous = scalar;
        scalar = CheckedAgreement(scalar, point);
        point = previous;
        if (!i) Require(scalar == Hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"), "RFC 7748 one iteration");
    }
    Require(scalar == Hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"), "RFC 7748 1000 iterations");
}

void EncodingsAndRejections() {
    const auto scalar = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const std::array<Bytes, 7> low_order{{
        SmallPoint(0), SmallPoint(1),
        Hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        Hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        Hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        Hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        Hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    }};
    PsaKey key; key.Import(scalar);
    for (auto point : low_order) {
        for (int high_bit = 0; high_bit < 2; ++high_bit) {
            const auto before = FastCalls();
            const auto rejected = Agreement(key, point);
            Require(rejected.status == PSA_ERROR_INVALID_ARGUMENT, "low-order X25519 input accepted or wrong error");
            RequireFastCalls(before, 0, "low-order point bypassed original public-key validation");
            CheckEquivalent(scalar, point);
            point[31] |= 0x80;
        }
    }
    // Every noncanonical encoding p+i fitting in 255 bits must agree with i,
    // including the rejected 0 and 1. The high encoding bit is ignored.
    for (unsigned char i = 0; i < 19; ++i) {
        Bytes noncanonical; noncanonical.fill(0xff);
        noncanonical[0] = static_cast<unsigned char>(0xed + i); noncanonical[31] = 0x7f;
        const auto canonical = Agreement(key, SmallPoint(i));
        for (int high_bit = 0; high_bit < 2; ++high_bit) {
            const auto encoded = Agreement(key, noncanonical);
            Require(encoded.status == canonical.status, "noncanonical X25519 acceptance changed");
            if (encoded.status == PSA_SUCCESS) Require(encoded.output == canonical.output, "noncanonical X25519 reduction changed");
            CheckEquivalent(scalar, noncanonical);
            noncanonical[31] |= 0x80;
        }
    }
    auto high = BasePoint(); high[31] |= 0x80;
    Require(CheckedAgreement(scalar, high) == CheckedAgreement(scalar, BasePoint()), "X25519 high bit not masked");
    // Scalar clamping must ignore bits 0..2 and 255, and force bit 254.
    auto clamped = scalar; clamped[0] &= 248; clamped[31] = static_cast<unsigned char>((clamped[31] & 127) | 64);
    const auto expected = CheckedAgreement(clamped, BasePoint());
    for (unsigned int bits = 0; bits < 32; ++bits) {
        auto variant = clamped;
        variant[0] = static_cast<unsigned char>(variant[0] | (bits & 7));
        variant[31] = static_cast<unsigned char>((variant[31] & 63) | ((bits & 8) ? 64 : 0) | ((bits & 16) ? 128 : 0));
        Require(CheckedAgreement(variant, BasePoint()) == expected, "X25519 scalar clamping changed");
        CheckEquivalent(variant, BasePoint());
    }
    std::array<unsigned char, 33> oversized{}; oversized[0] = 9;
    for (const std::size_t size : {std::size_t{0}, std::size_t{1}, std::size_t{31}, std::size_t{33}}) {
        const auto before = FastCalls();
        const auto rejected = Agreement(key, std::span(oversized).first(size));
        Require(rejected.status == PSA_ERROR_INVALID_ARGUMENT, "invalid X25519 public-key length accepted");
        RequireFastCalls(before, 0, "invalid-length point reached fast path");
        PsaKey invalid;
        auto attributes = Attributes();
        Require(psa_import_key(&attributes, oversized.data(), size, &invalid.value) == PSA_ERROR_INVALID_ARGUMENT,
                "invalid X25519 private-key length accepted");
    }
    Bytes output{}; std::size_t size = 0;
    Require(psa_export_public_key(key.value, output.data(), 31, &size) == PSA_ERROR_BUFFER_TOO_SMALL, "short public-key output accepted");
    const auto base = BasePoint();
    Require(psa_raw_key_agreement(PSA_ALG_ECDH, key.value, base.data(), base.size(), output.data(), 31, &size) == PSA_ERROR_BUFFER_TOO_SMALL,
            "short shared-secret output accepted");

    // Importing and exporting a public-only key must preserve its encoding;
    // it must not try to multiply a nonexistent private scalar.
    const auto public_key = Public(key);
    auto public_attributes = Attributes();
    psa_set_key_type(&public_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_usage_flags(&public_attributes, 0);
    psa_set_key_algorithm(&public_attributes, PSA_ALG_NONE);
    PsaKey public_only;
    const auto before = FastCalls();
    Require(psa_import_key(&public_attributes, public_key.data(), public_key.size(), &public_only.value) == PSA_SUCCESS,
            "X25519 public-only import");
    Require(psa_export_public_key(public_only.value, output.data(), output.size(), &size) == PSA_SUCCESS &&
            size == output.size() && output == public_key, "X25519 public-only export changed");
    RequireFastCalls(before, 0, "public-only export reached private-scalar fast path");
}

void Differential() {
    std::mt19937_64 random(0x5842553935323531ULL);
    for (int i = 0; i < 128; ++i) {
        const auto scalar = Next(random), arbitrary_point = Next(random), peer_scalar = Next(random);
        CheckEquivalent(scalar, arbitrary_point);
        CheckEquivalent(scalar, BasePoint());
        const auto peer_public = Generic(peer_scalar, BasePoint());
        Require(!peer_public.status, "generic random public key");
        CheckEquivalent(scalar, peer_public.output);
        PsaKey key; key.Import(scalar);
        const auto reference = Generic(scalar, BasePoint());
        Require(!reference.status && Public(key) == reference.output, "random PSA public export mismatch");
    }
    for (const unsigned char fill : {static_cast<unsigned char>(0), static_cast<unsigned char>(0xff)}) {
        Bytes scalar; scalar.fill(fill);
        CheckEquivalent(scalar, BasePoint());
    }
}

void FreshKeys() {
    std::set<Bytes> keys;
    const auto peer_scalar = Hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const auto peer_public = Generic(peer_scalar, BasePoint());
    Require(!peer_public.status, "fresh-key peer setup");
    for (int i = 0; i < 32; ++i) {
        PsaKey key; key.Generate();
        Bytes scalar{}; std::size_t size = 0;
        Require(psa_export_key(key.value, scalar.data(), scalar.size(), &size) == PSA_SUCCESS && size == scalar.size(), "fresh private key export");
        Require(keys.insert(scalar).second, "fresh X25519 private key was reused");
        const auto before = FastCalls();
        const auto public_key = Public(key);
        const auto secret = Agreement(key, peer_public.output);
        RequireFastCalls(before, 2, "fresh handshake did not accelerate both public and shared operations");
        const auto public_reference = Generic(scalar, BasePoint()), secret_reference = Generic(scalar, peer_public.output);
        Require(!public_reference.status && public_key == public_reference.output, "fresh public key differs from generic");
        Require(!secret_reference.status && secret.status == PSA_SUCCESS && secret.output == secret_reference.output,
                "fresh shared secret differs from generic");
        Require(CheckedAgreement(peer_scalar, public_key) == secret.output, "fresh bilateral agreement mismatch");
    }
}

void OtherCurvesStayGeneric() {
    Bytes scalar{}; scalar.back() = 1;
    PsaKey key;
    auto attributes = Attributes(PSA_ECC_FAMILY_SECP_R1, 256);
    Require(psa_import_key(&attributes, scalar.data(), scalar.size(), &key.value) == PSA_SUCCESS, "P-256 import");
    std::array<unsigned char, 65> public_key{}; std::size_t size = 0;
    const auto before = FastCalls();
    Require(psa_export_public_key(key.value, public_key.data(), public_key.size(), &size) == PSA_SUCCESS && size == 65, "P-256 public export");
    Require(public_key[0] == 4, "P-256 public encoding");
    Bytes secret{};
    Require(psa_raw_key_agreement(PSA_ALG_ECDH, key.value, public_key.data(), public_key.size(), secret.data(), secret.size(), &size) == PSA_SUCCESS && size == 32,
            "P-256 agreement");
    const auto generator_x = Hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    Require(secret == generator_x && std::equal(generator_x.begin(), generator_x.end(), public_key.begin() + 1), "P-256 result changed");
    RequireFastCalls(before, 0, "non-X25519 curve reached X25519 adapter");
}

void Parallel() {
    // Direct calls avoid global counter assertions racing one another; the
    // enclosing delta proves all operations reached the tested adapter.
#if defined(CONNECTCOIN_X25519_ACCELERATION)
    constexpr int workers = 4, iterations = 32;
    const auto before = FastCalls();
    std::array<std::exception_ptr, workers> errors{};
    std::vector<std::thread> threads;
    for (int worker = 0; worker < workers; ++worker) threads.emplace_back([&, worker] {
        try {
            std::mt19937_64 random(0x5448524541440000ULL + static_cast<unsigned int>(worker));
            for (int i = 0; i < iterations; ++i) {
                const auto scalar = Next(random), point = Next(random);
                const auto expected = Generic(scalar, point);
                Bytes actual{};
                const auto status = connectcoin_mbedtls_x25519_mul(actual.data(), scalar.data(), point.data());
                Require(!expected.status && !status && actual == expected.output, "parallel X25519 mismatch");
            }
        } catch (...) { errors[worker] = std::current_exception(); }
    });
    for (auto& thread : threads) thread.join();
    for (const auto& error : errors) if (error) std::rethrow_exception(error);
    RequireFastCalls(before, workers * iterations, "parallel fast-path invocation count");
#endif
}

void Benchmark() {
    // Run this same binary from acceleration ON and OFF builds. This measures
    // the unchanged public PSA call boundary, not incomparable raw primitives.
    constexpr int iterations = 256;
    std::mt19937_64 random(0x42454e43484d4152ULL);
    std::vector<Bytes> scalars;
    for (int i = 0; i < iterations; ++i) scalars.push_back(Next(random));
    const auto peer = Hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    unsigned int checksum = 0;
    for (int run = 0; run < 5; ++run) {
        const auto started = std::chrono::steady_clock::now();
        for (const auto& scalar : scalars) {
            PsaKey key; key.Import(scalar);
            const auto public_key = Public(key);
            const auto secret = Agreement(key, peer);
            Require(secret.status == PSA_SUCCESS, "benchmark agreement");
            checksum += public_key[0] + secret.output[0];
        }
        const auto elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
        std::cout << "X25519 PSA import+public+shared pairs=" << iterations << " run=" << run + 1 << " ms=" << elapsed << '\n';
    }
    std::cout << "X25519 benchmark checksum=" << checksum << '\n';
}
} // namespace

int main(int argc, char** argv) {
    try {
        Require(argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--benchmark"), "usage: claimer-x25519-tests [--benchmark]");
        claimer::InitializeCrypto();
        RfcVectors();
        EncodingsAndRejections();
        Differential();
        FreshKeys();
        OtherCurvesStayGeneric();
        Parallel();
#if defined(CONNECTCOIN_X25519_ACCELERATION)
        std::cout << "X25519 acceleration enabled";
#else
        std::cout << "X25519 generic fallback enabled";
#endif
#if defined(CONNECTCOIN_X25519_ACCELERATION) && defined(CONNECTCOIN_X25519_TESTING)
        std::cout << "; instrumented fast-path calls=" << FastCalls();
#endif
        std::cout << "\nnative X25519 regression tests passed\n";
        if (argc == 2) Benchmark();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
