// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#pragma once
#include <mbedtls/ssl.h>
#ifdef __cplusplus
extern "C" {
#endif
unsigned char* connectcoin_p2c_client_random(mbedtls_ssl_context* ssl);
/* Fetch/decrypt only. The caller must independently authenticate the returned
 * proof; this does not validate the CertificateVerify signature or advance TLS. */
int connectcoin_p2c_fetch_certificate_verify(mbedtls_ssl_context* ssl);
#ifdef __cplusplus
}
#endif
