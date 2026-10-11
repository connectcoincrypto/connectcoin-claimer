// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace claimer {
using Bytes = std::vector<unsigned char>;
using Hash = std::array<unsigned char, 32>;
struct Context {
    std::string domain;
    std::string txid;
    uint32_t input_index{};
    std::string connection_work_target;
    uint32_t root_certificates_version{1};
    uint8_t signature_algorithms_mask{7};
    int64_t validation_time{};
};
struct ParsedProof {
    std::span<const unsigned char> client_hello, server_hello, encrypted_extensions, certificate, certificate_verify;
    std::vector<std::span<const unsigned char>> certificate_chain;
    uint16_t certificate_verify_scheme{};
    std::span<const unsigned char> certificate_verify_signature;
    Hash transcript_hash{}, connection_work_hash{};
};
struct Verification {
    std::string work_hash; // Conventional display hex (reversed internal digest).
    bool meets_target{};
    uint16_t signature_scheme{};
};
// Fail closed with an exception on malformed data; no implicit system roots/time.
void ValidateContext(const Context& context);
bool IsCanonicalDomain(std::string_view domain);
Hash ClaimChallenge(const Context& context);
ParsedProof ParseProof(std::span<const unsigned char> proof, const Context& context);
Verification VerifyProof(std::span<const unsigned char> proof, const Context& context);
#ifdef CLAIMER_CRYPTO_TESTING
// Only compiled into the separate offline test binary, never production.
Verification VerifyProofForTesting(std::span<const unsigned char> proof, const Context& context, std::span<const unsigned char> roots_pem);
#endif
void ValidateCertificateMessage(std::span<const unsigned char> message);
void InitializeCrypto();
void RandomBytes(std::span<unsigned char> output);
std::string Hex(std::span<const unsigned char> bytes);
Bytes Unhex(std::string_view text);
} // namespace claimer
