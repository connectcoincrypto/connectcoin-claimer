// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#ifndef CONNECTCOIN_MBEDTLS_X25519_H
#define CONNECTCOIN_MBEDTLS_X25519_H

#include <stddef.h>
#include <stdint.h>
#include <mbedtls/ecp.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONNECTCOIN_X25519_ACCELERATION)
/* RFC 7748 scalar multiplication using the pinned bundled HACL implementation.
 * Inputs are copied, scalar clamping and the public-coordinate top-bit rule
 * are applied, and an all-zero output is rejected and cleared. */
int connectcoin_mbedtls_x25519_mul(unsigned char output[32],
                                 const unsigned char scalar[32],
                                 const unsigned char point[32]);

/* Internal PSA adapter: callers retain upstream key loading and validation.
 * Only the multiplication changes; serialization uses Mbed TLS itself. */
int connectcoin_mbedtls_x25519_mul_keypair(const mbedtls_ecp_keypair *key,
                                         const mbedtls_ecp_point *point,
                                         unsigned char *output, size_t capacity,
                                         size_t *output_length);
#if defined(CONNECTCOIN_X25519_TESTING)
uint64_t connectcoin_mbedtls_x25519_test_calls(void);
#endif
#endif

#ifdef __cplusplus
}
#endif
#endif
