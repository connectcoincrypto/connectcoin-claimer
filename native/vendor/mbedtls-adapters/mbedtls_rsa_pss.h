// Copyright (c) 2026 The ConnectCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef CONNECTCOIN_CRYPTO_MBEDTLS_RSA_PSS_H
#define CONNECTCOIN_CRYPTO_MBEDTLS_RSA_PSS_H

#include <mbedtls/asn1.h>
#include <mbedtls/pk.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Pinned-library adapter. Preserve RFC 4055 key restrictions independently of
 * the RSA arithmetic backend; rsaEncryption and id-RSASSA-PSS are not aliases.
 * Legacy key serialization and PSA conversion cannot preserve this metadata,
 * so the pinned adapter explicitly rejects those operations for PSS keys.
 */
int connectcoin_mbedtls_parse_pss_key(mbedtls_pk_context* key, const mbedtls_asn1_buf* params);
int connectcoin_mbedtls_pss_key(const mbedtls_pk_context* key);
int connectcoin_mbedtls_pss_allows(const mbedtls_pk_context* key, mbedtls_md_type_t hash,
                                 mbedtls_md_type_t mgf1_hash, int salt_len);
int connectcoin_mbedtls_rsa_tls_scheme_matches(const mbedtls_pk_context* key, uint16_t scheme);

#ifdef __cplusplus
}
#endif

#endif // CONNECTCOIN_CRYPTO_MBEDTLS_RSA_PSS_H
