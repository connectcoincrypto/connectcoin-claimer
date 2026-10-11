// Copyright (c) 2026 The ConnectCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls_rsa_pss.h"

#include <mbedtls/oid.h>

#include <string.h>

/* Parse the contents of a hash AlgorithmIdentifier, allowing only absent or
 * NULL parameters. Keeping this in mbedcrypto avoids a dependency on X.509.
 */
static int pss_hash_contents(unsigned char* p, const unsigned char* end,
                             mbedtls_md_type_t* hash)
{
    mbedtls_asn1_buf oid;
    size_t len;
    if (mbedtls_asn1_get_tag(&p, end, &oid.len, MBEDTLS_ASN1_OID) != 0) return -1;
    oid.tag = MBEDTLS_ASN1_OID;
    oid.p = p;
    p += oid.len;
    if (mbedtls_oid_get_md_alg(&oid, hash) != 0) return -1;
    if (p != end && (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_NULL) != 0 || len != 0)) return -1;
    return p == end ? 0 : -1;
}

int connectcoin_mbedtls_parse_pss_key(mbedtls_pk_context* key, const mbedtls_asn1_buf* params)
{
    mbedtls_md_type_t hash = MBEDTLS_MD_NONE;
    mbedtls_md_type_t mgf1_hash = MBEDTLS_MD_NONE;
    int min_salt_len = 0;

    /* RFC 4055 3.1: absent parameters mean unrestricted PSS. A present empty
     * SEQUENCE instead imposes the ASN.1 defaults SHA-1 / MGF1-SHA-1 / 20.
     */
    if (params->tag != 0) {
        unsigned char* p = params->p;
        const unsigned char* end = p + params->len;
        int previous_field = -1;
        if (params->tag != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) return MBEDTLS_ERR_PK_INVALID_ALG;
        hash = MBEDTLS_MD_SHA1;
        mgf1_hash = MBEDTLS_MD_SHA1;
        min_salt_len = 20;
        while (p != end) {
            size_t len;
            const unsigned char* field_end;
            const int field = *p - (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED);
            /* Reject duplicate, out-of-order, unknown, and implicit fields. */
            if (field < 0 || field > 3 || field <= previous_field ||
                mbedtls_asn1_get_tag(&p, end, &len,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | field) != 0) return MBEDTLS_ERR_PK_INVALID_ALG;
            field_end = p + len;
            if (field == 0) {
                if (mbedtls_asn1_get_tag(&p, field_end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0 ||
                    len != (size_t)(field_end - p) || pss_hash_contents(p, field_end, &hash) != 0) return MBEDTLS_ERR_PK_INVALID_ALG;
                p = (unsigned char*)field_end;
            } else if (field == 1) {
                mbedtls_asn1_buf oid, mgf_params;
                if (mbedtls_asn1_get_alg(&p, field_end, &oid, &mgf_params) != 0 ||
                    MBEDTLS_OID_CMP(MBEDTLS_OID_MGF1, &oid) != 0 ||
                    mgf_params.tag != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) ||
                    pss_hash_contents(mgf_params.p, mgf_params.p + mgf_params.len, &mgf1_hash) != 0) return MBEDTLS_ERR_PK_INVALID_ALG;
            } else {
                int value;
                if (mbedtls_asn1_get_int(&p, field_end, &value) != 0 || value < 0) return MBEDTLS_ERR_PK_INVALID_ALG;
                if (field == 2) min_salt_len = value;
                if (field == 3 && value != 1) return MBEDTLS_ERR_PK_INVALID_ALG;
            }
            if (p != field_end) return MBEDTLS_ERR_PK_INVALID_ALG;
            previous_field = field;
        }
    } else if (params->len != 0) {
        return MBEDTLS_ERR_PK_INVALID_ALG;
    }
    key->connectcoin_pss_key = 1;
    key->connectcoin_pss_hash = hash;
    key->connectcoin_pss_mgf1_hash = mgf1_hash;
    key->connectcoin_pss_min_salt_len = min_salt_len;
    return 0;
}

int connectcoin_mbedtls_pss_key(const mbedtls_pk_context* key)
{
    return key != NULL && key->connectcoin_pss_key;
}

int connectcoin_mbedtls_pss_allows(const mbedtls_pk_context* key, mbedtls_md_type_t hash,
                                 mbedtls_md_type_t mgf1_hash, int salt_len)
{
    if (!connectcoin_mbedtls_pss_key(key)) return 1;
    if (key->connectcoin_pss_hash == MBEDTLS_MD_NONE) return 1;
    /* A caller using ANY_SALT cannot establish the key's minimum restriction.
     * X.509 and TLS pass an exact salt length, which can be checked safely.
     */
    return hash == key->connectcoin_pss_hash && mgf1_hash == key->connectcoin_pss_mgf1_hash &&
           salt_len >= key->connectcoin_pss_min_salt_len;
}

int connectcoin_mbedtls_rsa_tls_scheme_matches(const mbedtls_pk_context* key, uint16_t scheme)
{
    mbedtls_md_type_t hash;
    int salt_len;
    int pss_scheme;
    if (key == NULL || mbedtls_pk_get_type(key) != MBEDTLS_PK_RSA) return 0;
    switch (scheme) {
    case 0x0804: case 0x0809: hash = MBEDTLS_MD_SHA256; salt_len = 32; break;
    case 0x0805: case 0x080a: hash = MBEDTLS_MD_SHA384; salt_len = 48; break;
    case 0x0806: case 0x080b: hash = MBEDTLS_MD_SHA512; salt_len = 64; break;
    default: return 0;
    }
    pss_scheme = scheme >= 0x0809;
    return pss_scheme == connectcoin_mbedtls_pss_key(key) &&
           connectcoin_mbedtls_pss_allows(key, hash, hash, salt_len);
}
