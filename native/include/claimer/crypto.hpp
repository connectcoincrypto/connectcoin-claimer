// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#pragma once
#include <array>
#include <cstdint>
#include <memory>
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
// Validated immutable-by-interface context. Owns its inputs and precomputes only
// public, deterministic values; never TLS secrets, key shares or nonces.
class PreparedContext {
    Context context_;
    Hash challenge_{}, target_{};
    bool valid_{true};
    void RequireValid() const;
public:
    explicit PreparedContext(const Context& context);
    PreparedContext(const PreparedContext&) = default;
    PreparedContext& operator=(const PreparedContext&);
    PreparedContext(PreparedContext&&) noexcept;
    PreparedContext& operator=(PreparedContext&&) noexcept;
    const Context& Get() const;
    const Hash& Challenge() const;
    const Hash& Target() const;
    // Equality of every static input, never bounty/outpoint identity alone.
    bool MatchesStaticContext(const Context& context) const noexcept;
    PreparedContext WithValidationTime(int64_t validation_time) const;
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
// Construction parses owned bytes exactly once. Copies/moves retain immutable
// backing storage, so ParsedProof spans can never outlive/mismatch those bytes.
// No API accepts a caller-created ParsedProof as an authenticated parse result.
class CapturedProof {
    struct Storage;
    std::shared_ptr<const Storage> storage_;
    friend Verification VerifyCaptured(const CapturedProof&);
#ifdef CLAIMER_CRYPTO_TESTING
    friend Verification VerifyCapturedForTesting(const CapturedProof&, std::span<const unsigned char>);
#endif
public:
    CapturedProof(Bytes encoded, const PreparedContext& context);
    const Bytes& Encoded() const;
};
// Fail closed with an exception on malformed data; no implicit system roots/time.
void ValidateContext(const Context& context);
bool IsCanonicalDomain(std::string_view domain);
Hash ClaimChallenge(const Context& context);
ParsedProof ParseProof(std::span<const unsigned char> proof, const Context& context);
Verification VerifyProof(std::span<const unsigned char> proof, const Context& context);
Verification VerifyCaptured(const CapturedProof& proof);
#ifdef CLAIMER_CRYPTO_TESTING
// Only compiled into the separate offline test binary, never production.
Verification VerifyProofForTesting(std::span<const unsigned char> proof, const Context& context, std::span<const unsigned char> roots_pem);
Verification VerifyCapturedForTesting(const CapturedProof& proof, std::span<const unsigned char> roots_pem);
struct SignatureCacheStats { size_t hits{}, misses{}, entries{}, bytes{}; };
SignatureCacheStats SignatureCacheStatsForTesting();
void ClearSignatureCacheForTesting();
struct CertificateCacheStats {
    size_t hits{}, misses{}, metadata_builds{}, time_checks{};
    size_t entries{}, bytes{}, estimated_bytes{};
};
CertificateCacheStats CertificateCacheStatsForTesting();
void ClearCertificateCacheForTesting();
#endif
void ValidateCertificateMessage(std::span<const unsigned char> message);
// Only a work filter, never authentication. The version-2 prefix must end
// exactly after Certificate; winners still require complete proof verification.
bool CertificatePrefixMeetsTarget(std::span<const unsigned char> prefix, const PreparedContext& context);
void InitializeCrypto();
void RandomBytes(std::span<unsigned char> output);
std::string Hex(std::span<const unsigned char> bytes);
Bytes Unhex(std::string_view text);
} // namespace claimer
