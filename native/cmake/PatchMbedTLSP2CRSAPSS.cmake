# Copyright (c) 2026 The ConnectCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Mbed TLS 3.6.7 has RSA-PSS arithmetic, but no PSS key-restriction metadata,
# and does not accept id-RSASSA-PSS SubjectPublicKeyInfo or TLS scheme 0x0809.
# Apply a narrow, auditable adapter to the pinned sources. Every replacement
# checks the expected upstream text, and is idempotent for existing builds.
if(NOT DEFINED MBEDTLS_SOURCE_DIR)
  message(FATAL_ERROR "MBEDTLS_SOURCE_DIR is required")
endif()

function(p2c_mbedtls_count contents needle result)
  set(remaining "${contents}")
  set(count 0)
  string(LENGTH "${needle}" needle_length)
  while(TRUE)
    string(FIND "${remaining}" "${needle}" position)
    if(position EQUAL -1)
      break()
    endif()
    math(EXPR count "${count} + 1")
    math(EXPR next "${position} + ${needle_length}")
    string(SUBSTRING "${remaining}" ${next} -1 remaining)
  endwhile()
  set(${result} "${count}" PARENT_SCOPE)
endfunction()

function(p2c_mbedtls_replace relative_path old_text new_text expected_count)
  set(path "${MBEDTLS_SOURCE_DIR}/${relative_path}")
  file(READ "${path}" contents)
  p2c_mbedtls_count("${contents}" "${new_text}" already_patched)
  if(already_patched EQUAL expected_count)
    return()
  elseif(NOT already_patched EQUAL 0)
    message(FATAL_ERROR "P2C RSA-PSS patch: ${relative_path} is only partially patched; review the pinned dependency")
  endif()
  p2c_mbedtls_count("${contents}" "${old_text}" count)
  if(NOT count EQUAL expected_count)
    message(FATAL_ERROR "P2C RSA-PSS patch: ${relative_path} expected ${expected_count} matches, found ${count}; review the pinned dependency")
  endif()
  string(REPLACE "${old_text}" "${new_text}" contents "${contents}")
  file(WRITE "${path}" "${contents}")
endfunction()

p2c_mbedtls_replace(include/mbedtls/pk.h [=[typedef struct mbedtls_pk_context {
]=] [=[typedef struct mbedtls_pk_context {
    /* ConnectCoin: original RFC 4055 key identity and restrictions. The RSA
     * method table remains the arithmetic backend, not the SPKI identity. */
    unsigned int MBEDTLS_PRIVATE(connectcoin_pss_key);
    mbedtls_md_type_t MBEDTLS_PRIVATE(connectcoin_pss_hash);
    mbedtls_md_type_t MBEDTLS_PRIVATE(connectcoin_pss_mgf1_hash);
    int MBEDTLS_PRIVATE(connectcoin_pss_min_salt_len);
]=] 1)

foreach(source IN ITEMS library/pk.c library/pkparse.c library/pkwrite.c library/ssl_tls13_generic.c)
  p2c_mbedtls_replace(${source} [=[#include "common.h"]=]
    [=[#include "common.h"
#include "mbedtls_rsa_pss.h"]=] 1)
endforeach()

# The legacy export APIs encode rsaEncryption/PKCS#1 or a PSA policy without
# RFC 4055 identity. P2C does not use them: reject PSS instead of silently
# stripping its restrictions. DER certificate bytes remain unchanged.
foreach(operation IN ITEMS pubkey key)
  p2c_mbedtls_replace(library/pkwrite.c
    "int mbedtls_pk_write_${operation}_der(const mbedtls_pk_context *key, unsigned char *buf, size_t size)\n{"
    "int mbedtls_pk_write_${operation}_der(const mbedtls_pk_context *key, unsigned char *buf, size_t size)\n{\n    if (connectcoin_mbedtls_pss_key(key)) {\n        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;\n    }" 1)
endforeach()
p2c_mbedtls_replace(library/pk.c
[=[int mbedtls_pk_get_psa_attributes(const mbedtls_pk_context *pk,
                                  psa_key_usage_t usage,
                                  psa_key_attributes_t *attributes)
{]=]
[=[int mbedtls_pk_get_psa_attributes(const mbedtls_pk_context *pk,
                                  psa_key_usage_t usage,
                                  psa_key_attributes_t *attributes)
{
    if (connectcoin_mbedtls_pss_key(pk)) {
        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }]=] 1)
p2c_mbedtls_replace(library/pk.c
[=[    /* Set the output immediately so that it won't contain garbage even
     * if we error out before calling psa_import_key(). */
    *key_id = MBEDTLS_SVC_KEY_ID_INIT;]=]
[=[    /* Set the output immediately so that it won't contain garbage even
     * if we error out before calling psa_import_key(). */
    *key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (connectcoin_mbedtls_pss_key(pk)) {
        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }]=] 1)

p2c_mbedtls_replace(library/pk.c
[=[void mbedtls_pk_init(mbedtls_pk_context *ctx)
{]=]
[=[void mbedtls_pk_init(mbedtls_pk_context *ctx)
{
    ctx->connectcoin_pss_key = 0;
    ctx->connectcoin_pss_hash = MBEDTLS_MD_NONE;
    ctx->connectcoin_pss_mgf1_hash = MBEDTLS_MD_NONE;
    ctx->connectcoin_pss_min_salt_len = 0;]=] 1)

p2c_mbedtls_replace(library/pkparse.c [=[    ret = mbedtls_oid_get_pk_alg(&alg_oid, pk_alg);]=]
[=[    /* ConnectCoin: preserve PSS identity until setup records constraints. */
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_RSASSA_PSS, &alg_oid) == 0) {
        *pk_alg = MBEDTLS_PK_RSASSA_PSS;
        return 0;
    }
    ret = mbedtls_oid_get_pk_alg(&alg_oid, pk_alg);]=] 1)

p2c_mbedtls_replace(library/pkparse.c
[=[    if ((pk_info = mbedtls_pk_info_from_type(pk_alg)) == NULL) {]=]
[=[    if ((pk_info = mbedtls_pk_info_from_type(
             pk_alg == MBEDTLS_PK_RSASSA_PSS ? MBEDTLS_PK_RSA : pk_alg)) == NULL) {]=] 2)

p2c_mbedtls_replace(library/pkparse.c
[=[    if (pk_alg == MBEDTLS_PK_RSA) {
        ret = mbedtls_rsa_parse_pubkey]=]
[=[    if (pk_alg == MBEDTLS_PK_RSASSA_PSS &&
        (ret = connectcoin_mbedtls_parse_pss_key(pk, &alg_params)) != 0) {
        mbedtls_pk_free(pk);
        return ret;
    }
    if (pk_alg == MBEDTLS_PK_RSA || pk_alg == MBEDTLS_PK_RSASSA_PSS) {
        ret = mbedtls_rsa_parse_pubkey]=] 1)

p2c_mbedtls_replace(library/pkparse.c
[=[    if (pk_alg == MBEDTLS_PK_RSA) {
        if ((ret = mbedtls_rsa_parse_key]=]
[=[    if (pk_alg == MBEDTLS_PK_RSASSA_PSS &&
        (ret = connectcoin_mbedtls_parse_pss_key(pk, &params)) != 0) {
        mbedtls_pk_free(pk);
        return ret;
    }
    if (pk_alg == MBEDTLS_PK_RSA || pk_alg == MBEDTLS_PK_RSASSA_PSS) {
        if ((ret = mbedtls_rsa_parse_key]=] 1)

p2c_mbedtls_replace(library/pk.c [=[    return ctx->pk_info->can_do(type);]=]
[=[    if (connectcoin_mbedtls_pss_key(ctx) && type != MBEDTLS_PK_RSASSA_PSS) {
        return 0;
    }
    return ctx->pk_info->can_do(type);]=] 1)

# Direct PK APIs select PKCS#1 v1.5. A PSS key must use the _ext PSS API.
p2c_mbedtls_replace(library/pk.c
[=[                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                mbedtls_pk_restart_ctx *rs_ctx)
{
    if]=]
[=[                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                mbedtls_pk_restart_ctx *rs_ctx)
{
    if (connectcoin_mbedtls_pss_key(ctx)) {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }
    if]=] 1)
p2c_mbedtls_replace(library/pk.c
[=[                                  const unsigned char *sig, size_t sig_len,
                                  mbedtls_pk_restart_ctx *rs_ctx)
{
    if]=]
[=[                                  const unsigned char *sig, size_t sig_len,
                                  mbedtls_pk_restart_ctx *rs_ctx)
{
    if (connectcoin_mbedtls_pss_key(ctx)) {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }
    if]=] 1)

p2c_mbedtls_replace(library/pk.c
[=[    pss_opts = (const mbedtls_pk_rsassa_pss_options *) options;]=]
[=[    pss_opts = (const mbedtls_pk_rsassa_pss_options *) options;
    if (!connectcoin_mbedtls_pss_allows(ctx, md_alg, pss_opts->mgf1_hash_id,
                                      pss_opts->expected_salt_len)) {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }]=] 1)

# Upstream's PSA ANY_SALT fast path otherwise ignores expected_salt_len.
# Keep it only for callers that explicitly request ANY_SALT; exact lengths
# use the already-present RSA verification path (TLS requires hash length).
p2c_mbedtls_replace(library/pk.c
[=[    if (pss_opts->mgf1_hash_id == md_alg) {]=]
[=[    if (pss_opts->mgf1_hash_id == md_alg &&
        pss_opts->expected_salt_len == MBEDTLS_RSA_SALT_LEN_ANY) {]=] 1)

p2c_mbedtls_replace(library/pk.c
[=[    if (pk_type != MBEDTLS_PK_RSASSA_PSS) {
        return mbedtls_pk_sign]=]
[=[    if (connectcoin_mbedtls_pss_key(ctx)) {
        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(md_alg);
        if (md == NULL || !connectcoin_mbedtls_pss_allows(
                ctx, md_alg, md_alg, mbedtls_md_get_size(md))) {
            return MBEDTLS_ERR_PK_TYPE_MISMATCH;
        }
    }
    if (pk_type != MBEDTLS_PK_RSASSA_PSS) {
        return mbedtls_pk_sign]=] 1)

# Encrypted-PK and generic PSA capabilities must not bypass key restrictions.
p2c_mbedtls_replace(library/pk.c
[=[    /* Filter out non allowed algorithms */]=]
[=[    if (connectcoin_mbedtls_pss_key(ctx)) {
        const mbedtls_md_type_t md = mbedtls_md_type_from_psa_alg(PSA_ALG_SIGN_GET_HASH(alg));
        if (!PSA_ALG_IS_RSA_PSS(alg) ||
            !connectcoin_mbedtls_pss_allows(ctx, md, md,
                (int) PSA_HASH_LENGTH(PSA_ALG_SIGN_GET_HASH(alg)))) {
            return 0;
        }
    }
    /* Filter out non allowed algorithms */]=] 1)
foreach(operation IN ITEMS encrypt decrypt)
  p2c_mbedtls_replace(library/pk.c
    "    if (ctx->pk_info->${operation}_func == NULL) {"
    "    if (connectcoin_mbedtls_pss_key(ctx) || ctx->pk_info->${operation}_func == NULL) {" 1)
endforeach()

# Advertise and decode actual PSS SPKI schemes. Preserve the other existing
# library hash variants; ConnectCoin's protocol only configures SHA-256.
foreach(hash IN ITEMS 256 384 512)
  p2c_mbedtls_replace(library/ssl_misc.h
    "        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA${hash}:"
    "        case MBEDTLS_TLS1_3_SIG_RSA_PSS_PSS_SHA${hash}:\n        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA${hash}:" 2)
  p2c_mbedtls_replace(library/ssl_tls13_server.c
    "        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA${hash}:"
    "        case MBEDTLS_TLS1_3_SIG_RSA_PSS_PSS_SHA${hash}:\n        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA${hash}:" 1)
endforeach()

p2c_mbedtls_replace(library/ssl_tls13_generic.c
[=[    if (!mbedtls_pk_can_do(&ssl->session_negotiate->peer_cert->pk, sig_alg)) {]=]
[=[    if (!mbedtls_pk_can_do(&ssl->session_negotiate->peer_cert->pk, sig_alg) ||
        !mbedtls_ssl_tls13_check_sig_alg_cert_key_match(
            algorithm, &ssl->session_negotiate->peer_cert->pk)) {]=] 1)

p2c_mbedtls_replace(library/ssl_tls13_generic.c
[=[    mbedtls_pk_type_t pk_type = (mbedtls_pk_type_t) mbedtls_ssl_sig_from_pk(key);]=]
[=[    if (mbedtls_pk_get_type(key) == MBEDTLS_PK_RSA) {
        return connectcoin_mbedtls_rsa_tls_scheme_matches(key, sig_alg);
    }
    mbedtls_pk_type_t pk_type = (mbedtls_pk_type_t) mbedtls_ssl_sig_from_pk(key);]=] 1)

# A PKCS#1 private key can legitimately accompany a PSS certificate. Select
# the TLS scheme from the certificate SPKI; pk_sign_ext enforces any private
# key restrictions separately. This also prevents selecting RSAE for PSS certs.
p2c_mbedtls_replace(library/ssl_tls13_generic.c
[=[        if (!mbedtls_ssl_tls13_check_sig_alg_cert_key_match(*sig_alg, own_key)) {]=]
[=[        if (!mbedtls_ssl_tls13_check_sig_alg_cert_key_match(
                *sig_alg, &mbedtls_ssl_own_cert(ssl)->pk)) {]=] 1)
