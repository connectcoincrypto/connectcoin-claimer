// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#pragma once
/* Verification uses the explicitly supplied block median time and pinned roots. */
#undef MBEDTLS_NET_C
#undef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE
#undef MBEDTLS_FS_IO
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT
#undef MBEDTLS_THREADING_PTHREAD
/* Replace compression only, keeping the complete provider hash lifecycle. */
#if defined(CONNECTCOIN_SHA256_ACCELERATION)
#undef MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
#undef MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY
#undef MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT
#undef MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY
#define MBEDTLS_SHA256_PROCESS_ALT
#endif
