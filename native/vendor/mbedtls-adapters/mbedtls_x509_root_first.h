// Copyright (c) 2026 The ConnectCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef CONNECTCOIN_CRYPTO_MBEDTLS_X509_ROOT_FIRST_H
#define CONNECTCOIN_CRYPTO_MBEDTLS_X509_ROOT_FIRST_H

#include <mbedtls/x509_crt.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Diagnostic observer, called immediately before a certificate-signature
 * attempt. It must not mutate certificates, verification state or key caches,
 * and must not reenter the verifier. Production callers pass NULL.
 */
typedef void (*connectcoin_mbedtls_x509_signature_observer)(
    void* context, const mbedtls_x509_crt* child, const mbedtls_x509_crt* parent);

/** Root-first verification for ConnectCoin's pinned, clockless Mbed TLS 3.6.7.
 *
 * Preserves acceptance and parent selection of verify_with_profile with static
 * roots, no CRLs, no verification callbacks and no restart context. Trusted-root
 * candidates must still prove their signatures during selection; untrusted
 * parent signatures are deferred until an anchor is found, then checked from
 * that anchor toward the leaf, stopping at the first invalid signature. Trusted
 * end entities retain the upstream exact-DER/self-issued exception.
 *
 * This is not a general replacement for Mbed TLS's callback/restartable APIs.
 * It does not check consensus dates, TLS leaf usage, RSA exponent limits or a
 * TLS CertificateVerify signature: callers retain those separate checks. Flags
 * report the first failure, not necessarily every failure the legacy API would
 * collect. Success is exactly a return value of zero and zero flags.
 *
 * Parsed keys can acquire internal arithmetic caches. Callers must serialize
 * access to shared roots just as with the legacy verifier. No ownership of any
 * input is transferred. crt, profile and flags must be non-NULL. cn may be NULL
 * to skip hostname verification, and trust_ca may be NULL for an empty store.
 */
int connectcoin_mbedtls_x509_crt_verify_root_first(
    mbedtls_x509_crt* crt, mbedtls_x509_crt* trust_ca,
    const mbedtls_x509_crt_profile* profile, const char* cn, uint32_t* flags,
    connectcoin_mbedtls_x509_signature_observer observer, void* observer_context);

#ifdef __cplusplus
}
#endif

#endif // CONNECTCOIN_CRYPTO_MBEDTLS_X509_ROOT_FIRST_H
