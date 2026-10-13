// Copyright (c) 2026 The ConnectCoin developers.
// Original layout adapters are MIT-licensed, adapted from ConnectCoin Core.
// Certificate structural parsing is adapted from Mbed TLS 3.6.7
// library/ssl_tls13_generic.c, Copyright The Mbed TLS Contributors, and used
// under its Apache-2.0 license option. Dependency licenses ship with the helper.
// SPDX-License-Identifier: MIT AND Apache-2.0
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "p2c_tls_private.h"
#include <ssl_misc.h>
#include <mbedtls/version.h>
#ifdef CLAIMER_NETWORK_TESTING
#include <mbedtls/psa_util.h>
#endif
#include <string.h>
#if MBEDTLS_VERSION_NUMBER != 0x03060700
#error "Review P2C TLS capture when upgrading Mbed TLS"
#endif
unsigned char* connectcoin_p2c_client_random(mbedtls_ssl_context* ssl)
{
    return ssl->handshake ? ssl->handshake->randbytes : NULL;
}
/* Structural portion of Mbed TLS 3.6.7 ssl_tls13_parse_certificate(). Keep its
 * bounds, per-entry extension mask and original extension-admission function.
 * The normal parser repeats DER/PK allocation for every connection even with
 * VERIFY_NONE. Capture instead calls ValidateCertificateMessage on these exact
 * bytes before fetching CV; that owns/reuses the complete parsed chain, never
 * a trust result. Full chain/name/time/usage/CV/target checks remain mandatory.
 */
static int capture_certificate_structure(mbedtls_ssl_context* ssl,
                                         const unsigned char* p,
                                         const unsigned char* end)
{
    size_t certificate_list_len;
    const unsigned char* certificate_list_end;
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 4);
    certificate_list_len = MBEDTLS_GET_UINT24_BE(p, 1);
    if (p[0] != 0 || certificate_list_len >= 0x10000) {
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                    MBEDTLS_ERR_SSL_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    p += 4;
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, certificate_list_len);
    certificate_list_end = p + certificate_list_len;
    while (p < certificate_list_end) {
        size_t cert_data_len, extensions_len;
        const unsigned char* extensions_end;
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, 3);
        cert_data_len = MBEDTLS_GET_UINT24_BE(p, 0);
        p += 3;
        if (cert_data_len < 128 || cert_data_len >= 0x10000) {
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                        MBEDTLS_ERR_SSL_DECODE_ERROR);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, cert_data_len);
        p += cert_data_len;
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, 2);
        extensions_len = MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, extensions_len);
        extensions_end = p + extensions_len;
        ssl->handshake->received_extensions = MBEDTLS_SSL_EXT_MASK_NONE;
        while (p < extensions_end) {
            unsigned int extension_type;
            size_t extension_data_len;
            int ret;
            MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, 4);
            extension_type = MBEDTLS_GET_UINT16_BE(p, 0);
            extension_data_len = MBEDTLS_GET_UINT16_BE(p, 2);
            p += 4;
            MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, extension_data_len);
            ret = mbedtls_ssl_tls13_check_received_extension(
                ssl, MBEDTLS_SSL_HS_CERTIFICATE, extension_type,
                MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CT);
            if (ret != 0) return ret;
            p += extension_data_len;
        }
    }
    if (p != end) {
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                    MBEDTLS_ERR_SSL_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    /* The original client handler rejects an empty chain even in VERIFY_NONE. */
    if (certificate_list_len == 0) {
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_NO_CERT,
                                    MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE);
        return MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE;
    }
    return 0;
}
int connectcoin_p2c_fetch_certificate(mbedtls_ssl_context* ssl)
{
    unsigned char* body = NULL;
    size_t length = 0;
    int ret;
    if (ssl == NULL || ssl->conf == NULL || ssl->handshake == NULL ||
        ssl->session_negotiate == NULL || ssl->session_negotiate->peer_cert != NULL ||
        ssl->state != MBEDTLS_SSL_SERVER_CERTIFICATE ||
        ssl->tls_version != MBEDTLS_SSL_VERSION_TLS1_3 ||
        ssl->conf->endpoint != MBEDTLS_SSL_IS_CLIENT ||
        ssl->conf->authmode != MBEDTLS_SSL_VERIFY_NONE)
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    ret = mbedtls_ssl_tls13_fetch_handshake_msg(ssl, MBEDTLS_SSL_HS_CERTIFICATE,
                                              &body, &length);
    if (ret != 0) return ret;
    ret = capture_certificate_structure(ssl, body, body + length);
    if (ret != 0) return ret;
    /* This capture path stops after fetching CertificateVerify and never
     * authenticates Finished or derives application traffic keys. Its TLS
     * transcript checksum is therefore no longer consumed. The owned proof
     * parser independently hashes the exact captured messages, and the full
     * verifier authenticates the certificate chain and CertificateVerify.
     * Completed handshakes use the original Mbed TLS certificate handler. */
    mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_CERTIFICATE_VERIFY);
    return 0;
}
int connectcoin_p2c_fetch_certificate_verify(mbedtls_ssl_context* ssl)
{
    unsigned char* body = NULL;
    size_t length = 0;
    if (ssl->state != MBEDTLS_SSL_CERTIFICATE_VERIFY) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    return mbedtls_ssl_tls13_fetch_handshake_msg(ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                                               &body, &length);
}
#ifdef CLAIMER_NETWORK_TESTING
static int forbidden_abbreviated_checksum(mbedtls_ssl_context* ssl,
                                         const unsigned char* message,
                                         size_t length)
{
    (void) ssl;
    (void) message;
    (void) length;
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
int connectcoin_p2c_test_certificate(const unsigned char* message, size_t length,
                                   int abbreviated, uint32_t sent_extensions,
                                   uint32_t* received_extensions, int* peer_present)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    int ret;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    *received_extensions = 0;
    *peer_present = 0;
    ret = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) goto cleanup;
    mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&config, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE);
    ret = mbedtls_ssl_setup(&ssl, &config);
    if (ret != 0) goto cleanup;
    if (message == NULL || length < 4 ||
        length > MBEDTLS_SSL_IN_BUFFER_LEN - (size_t)(ssl.in_msg - ssl.in_buf)) {
        ret = MBEDTLS_ERR_SSL_DECODE_ERROR;
        goto cleanup;
    }
    /* Only the test executable injects a previously reassembled message. Real
     * capture always enters through the authenticated record/reassembly layer. */
    memcpy(ssl.in_msg, message, length);
    ssl.in_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl.in_msglen = length;
    ssl.in_hslen = length;
    ssl.keep_current_message = 1;
    ssl.handshake->sent_extensions = sent_extensions;
    /* A valid abbreviated fixture must still succeed with checksum updates
     * forbidden. The original full-handshake branch retains its real checksum,
     * so differential fixtures also protect that branch from this optimization. */
    if (abbreviated) ssl.handshake->update_checksum = forbidden_abbreviated_checksum;
    mbedtls_ssl_handshake_set_state(&ssl, MBEDTLS_SSL_SERVER_CERTIFICATE);
    ret = abbreviated ? connectcoin_p2c_fetch_certificate(&ssl)
                      : mbedtls_ssl_tls13_process_certificate(&ssl);
    *received_extensions = ssl.handshake->received_extensions;
    *peer_present = ssl.session_negotiate->peer_cert != NULL;
cleanup:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&config);
    return ret;
}
#endif
