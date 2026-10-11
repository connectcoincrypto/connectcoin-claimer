// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#pragma once
#include <mbedtls/sha256.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Reference functions compile the unchanged pinned provider under private names.
 * The compression routine is also the production CPU-independent fallback. */
int connectcoin_sha256_portable_process(mbedtls_sha256_context*, const unsigned char[64]);
void connectcoin_sha256_reference_init(mbedtls_sha256_context*);
void connectcoin_sha256_reference_free(mbedtls_sha256_context*);
void connectcoin_sha256_reference_clone(mbedtls_sha256_context*, const mbedtls_sha256_context*);
int connectcoin_sha256_reference_starts(mbedtls_sha256_context*, int);
int connectcoin_sha256_reference_update(mbedtls_sha256_context*, const unsigned char*, size_t);
int connectcoin_sha256_reference_finish(mbedtls_sha256_context*, unsigned char*);
int connectcoin_sha256_reference(const unsigned char*, size_t, unsigned char*, int);

#if defined(CONNECTCOIN_SHA256_ACCELERATION)
/* True only when the compiled backend AND all CPU prerequisites are available. */
int connectcoin_sha256_hardware_available(void);
#if defined(CONNECTCOIN_SHA256_TESTING)
uint64_t connectcoin_sha256_test_hardware_calls(void);
uint64_t connectcoin_sha256_test_portable_calls(void);
/* Thread-local override, never compiled into production. Other threads retain
 * their automatic CPU dispatch while a test exercises the portable path. */
void connectcoin_sha256_test_force_portable(int);
#endif
#endif
#ifdef __cplusplus
}
#endif
