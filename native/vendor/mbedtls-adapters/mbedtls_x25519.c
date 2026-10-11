// Copyright (c) 2026 The ConnectCoin developers. MIT license.
// No new curve arithmetic: use the HACL code in pinned Mbed TLS 3.6.7.
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls_x25519.h"
#include <mbedtls/platform_util.h>
#include <mbedtls/version.h>
#if !(defined(__SIZEOF_INT128__) && (__SIZEOF_INT128__ == 16))
#define KRML_VERIFIED_UINT128
#endif
#include <everest/Hacl_Curve25519.h>
#include <string.h>

#if MBEDTLS_VERSION_NUMBER != 0x03060700
#error "Review the X25519 adapter before changing pinned Mbed TLS"
#endif

#if defined(CONNECTCOIN_X25519_TESTING)
#if defined(_MSC_VER)
#include <intrin.h>
static volatile __int64 test_calls;
static void record_call(void) { (void) _InterlockedIncrement64(&test_calls); }
uint64_t connectcoin_mbedtls_x25519_test_calls(void) {
    return (uint64_t) _InterlockedCompareExchange64(&test_calls, 0, 0);
}
#else
static uint64_t test_calls;
static void record_call(void) { (void) __atomic_fetch_add(&test_calls, 1, __ATOMIC_RELAXED); }
uint64_t connectcoin_mbedtls_x25519_test_calls(void) {
    return __atomic_load_n(&test_calls, __ATOMIC_RELAXED);
}
#endif
#endif

int connectcoin_mbedtls_x25519_mul(unsigned char output[32],
                                 const unsigned char scalar[32],
                                 const unsigned char point[32])
{
    unsigned char secret[32], coordinate[32];
    unsigned char nonzero = 0;
    size_t i;
    memcpy(secret, scalar, sizeof(secret));
    memcpy(coordinate, point, sizeof(coordinate));
    coordinate[31] &= 0x7f;
#if defined(CONNECTCOIN_X25519_TESTING)
    record_call();
#endif
    /* HACL clamps its private scalar and uses a constant-trace ladder. Its
     * native uint128 and portable legacy variants come from the same archive. */
    Hacl_Curve25519_crypto_scalarmult(output, secret, coordinate);
    mbedtls_platform_zeroize(secret, sizeof(secret));
    mbedtls_platform_zeroize(coordinate, sizeof(coordinate));
    for (i = 0; i < 32; ++i) nonzero |= output[i];
    if (nonzero == 0) {
        mbedtls_platform_zeroize(output, 32);
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }
    return 0;
}

int connectcoin_mbedtls_x25519_mul_keypair(const mbedtls_ecp_keypair *key,
                                         const mbedtls_ecp_point *point,
                                         unsigned char *output, size_t capacity,
                                         size_t *output_length)
{
    unsigned char scalar[32] = {0}, coordinate[32] = {0};
    size_t scalar_length = 0, coordinate_length = 0;
    int result = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    *output_length = 0;
    if (key->grp.id != MBEDTLS_ECP_DP_CURVE25519) goto cleanup;
    if (capacity < 32) {
        result = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        goto cleanup;
    }
    result = mbedtls_ecp_write_key_ext(key, &scalar_length, scalar, sizeof(scalar));
    if (result != 0) goto cleanup;
    result = mbedtls_ecp_point_write_binary(&key->grp, point,
        MBEDTLS_ECP_PF_UNCOMPRESSED, &coordinate_length, coordinate, sizeof(coordinate));
    if (result != 0) goto cleanup;
    if (scalar_length != 32 || coordinate_length != 32) {
        result = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
    result = connectcoin_mbedtls_x25519_mul(output, scalar, coordinate);
    if (result == 0) *output_length = 32;
cleanup:
    mbedtls_platform_zeroize(scalar, sizeof(scalar));
    mbedtls_platform_zeroize(coordinate, sizeof(coordinate));
    if (result != 0) mbedtls_platform_zeroize(output, capacity);
    return result;
}
