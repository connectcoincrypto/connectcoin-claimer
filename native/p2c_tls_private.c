// Copyright (c) 2026 The ConnectCoin developers. MIT license.
// Pinned Mbed TLS 3.6.7 layout adapter, adapted from ConnectCoin Core.
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "p2c_tls_private.h"
#include <ssl_misc.h>
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER != 0x03060700
#error "Review P2C TLS capture when upgrading Mbed TLS"
#endif
unsigned char* connectcoin_p2c_client_random(mbedtls_ssl_context* ssl)
{
    return ssl->handshake ? ssl->handshake->randbytes : NULL;
}
int connectcoin_p2c_fetch_certificate_verify(mbedtls_ssl_context* ssl)
{
    unsigned char* body = NULL;
    size_t length = 0;
    if (ssl->state != MBEDTLS_SSL_CERTIFICATE_VERIFY) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    return mbedtls_ssl_tls13_fetch_handshake_msg(ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                                               &body, &length);
}
