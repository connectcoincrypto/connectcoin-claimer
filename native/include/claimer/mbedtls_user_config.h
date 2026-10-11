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
