# Copyright (c) 2026 The ConnectCoin developers. MIT license.
# A TLS Certificate may span records. Keep each record limited to 16384 bytes,
# but reserve bounded extra input space for its handshake reassembly. Expanding
# allocation alone avoids a second transcript parser and pointer-moving realloc.
if(NOT DEFINED MBEDTLS_SOURCE_DIR OR NOT COMMAND p2c_mbedtls_replace)
  message(FATAL_ERROR "Load the pinned Mbed TLS checked replacement helper first")
endif()
set(reassembly_old [=[
#if !defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_IN_PAYLOAD_LEN))
#else
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_IN_PAYLOAD_LEN) \
     + (MBEDTLS_SSL_CID_IN_LEN_MAX))
#endif
]=])
set(reassembly_new [=[
/* ConnectCoin: bounded P2C Certificate reassembly across ordinary TLS records.
 * This expands allocation, NOT MBEDTLS_SSL_IN_CONTENT_LEN or record limits.
 * The extra current-record capacity is needed when a final fragment also
 * contains the following handshake message. Wire/proof caps remain separate.
 */
#if !defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_IN_PAYLOAD_LEN) + 49152)
#else
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_IN_PAYLOAD_LEN) \
     + (MBEDTLS_SSL_CID_IN_LEN_MAX) + 49152)
#endif
]=])
p2c_mbedtls_replace(library/ssl_misc.h "${reassembly_old}" "${reassembly_new}" 1)
unset(reassembly_old)
unset(reassembly_new)
