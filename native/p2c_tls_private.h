// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#pragma once
#include <mbedtls/ssl.h>
#ifdef __cplusplus
extern "C" {
#endif
unsigned char* connectcoin_p2c_client_random(mbedtls_ssl_context* ssl);
/* Abbreviated capture only: retain the pinned TLS Certificate envelope and
 * extension-admission checks, but leave DER parsing/authentication to the
 * caller's exact-byte owned certificate cache and full proof verifier.
 * Advances to CertificateVerify only after successful fetch/structure checks.
 * Does not update the discarded TLS transcript checksum; the owned proof
 * verifier hashes/authenticates the captured transcript independently. It
 * must never be used for a completed TLS handshake. */
int connectcoin_p2c_fetch_certificate(mbedtls_ssl_context* ssl);
/* Fetch/decrypt only. The caller must independently authenticate the returned
 * proof; this does not validate the CertificateVerify signature or advance TLS. */
int connectcoin_p2c_fetch_certificate_verify(mbedtls_ssl_context* ssl);
#ifdef CLAIMER_NETWORK_TESTING
/* Test-only private-state inspection; reports no secrets or key material. */
int connectcoin_p2c_test_tls_reset_clean(const mbedtls_ssl_context* ssl);
/* Test-only differential seam: feed an already reassembled handshake message
 * through the new capture path or the original Mbed TLS certificate handler.
 * This does not authenticate certificates or expose a production entry point. */
int connectcoin_p2c_test_certificate(const unsigned char* message, size_t length,
                                   int abbreviated, uint32_t sent_extensions,
                                   uint32_t* received_extensions, int* peer_present);
#endif
#ifdef __cplusplus
}
#endif
