// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#ifndef CLAIMER_THREADING_ALT_H
#define CLAIMER_THREADING_ALT_H
/* C-compatible storage; callbacks own one independent C++ std::mutex. */
typedef struct mbedtls_threading_mutex_t { void* mutex; } mbedtls_threading_mutex_t;
#endif
