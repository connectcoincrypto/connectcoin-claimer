// Copyright (c) 2026 The ConnectCoin developers. MIT license.
// Compile the unchanged Mbed TLS 3.6.7 implementation under private names.
// This preserves the stock compression, temporary zeroization and error codes,
// and provides a genuinely independent full-hash reference for offline tests.
#include <mbedtls/build_info.h>
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER != 0x03060700
#error "Review SHA-256 fallback before changing pinned Mbed TLS"
#endif
#undef MBEDTLS_SHA256_PROCESS_ALT
#undef MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
#undef MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY
#undef MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT
#undef MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY
#define mbedtls_internal_sha256_process connectcoin_sha256_portable_process
#define mbedtls_sha256_init connectcoin_sha256_reference_init
#define mbedtls_sha256_free connectcoin_sha256_reference_free
#define mbedtls_sha256_clone connectcoin_sha256_reference_clone
#define mbedtls_sha256_starts connectcoin_sha256_reference_starts
#define mbedtls_sha256_update connectcoin_sha256_reference_update
#define mbedtls_sha256_finish connectcoin_sha256_reference_finish
#define mbedtls_sha256 connectcoin_sha256_reference
#define mbedtls_sha256_self_test connectcoin_sha256_reference_self_test
#define mbedtls_sha224_self_test connectcoin_sha224_reference_self_test
#include "sha256.c"
