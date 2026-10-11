// Copyright (c) 2026 The ConnectCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/* Included at the end of the pinned library/x509_crt.c, not compiled as a
 * separate translation unit. Reuse its private name/profile/usage/signature
 * helpers rather than introducing a second interpretation of X.509 fields.
 * The legacy Mbed TLS entry points and their callback semantics are untouched.
 */
#include "mbedtls_x509_root_first.h"

#if MBEDTLS_VERSION_NUMBER != 0x03060700
#error "Review the ConnectCoin root-first adapter before changing pinned Mbed TLS"
#endif

#if defined(MBEDTLS_HAVE_TIME) || defined(MBEDTLS_HAVE_TIME_DATE)
#error "ConnectCoin root-first verification requires the clockless consensus configuration"
#endif

/* This is the structural portion of x509_crt_find_parent_in, including its
 * stored max_pathlen convention and self-issued count. In the clockless build
 * upstream takes the first structurally suitable untrusted parent even when
 * its signature is invalid; introducing backtracking would change consensus.
 */
static int connectcoin_x509_parent_matches(const mbedtls_x509_crt* child,
                                          const mbedtls_x509_crt* parent,
                                          int trusted, unsigned path_count,
                                          unsigned self_count)
{
    if (x509_crt_check_parent(child, parent, trusted) != 0) return 0;
    if (parent->max_pathlen > 0 &&
        (size_t) parent->max_pathlen < 1 + path_count - self_count) return 0;
    return 1;
}

static int connectcoin_x509_check_signature(
    mbedtls_x509_crt* child, mbedtls_x509_crt* parent,
    connectcoin_mbedtls_x509_signature_observer observer, void* observer_context)
{
    if (observer != NULL) observer(observer_context, child, parent);
    return x509_crt_check_signature(child, parent, NULL);
}

int connectcoin_mbedtls_x509_crt_verify_root_first(
    mbedtls_x509_crt* crt, mbedtls_x509_crt* trust_ca,
    const mbedtls_x509_crt_profile* profile, const char* cn, uint32_t* flags,
    connectcoin_mbedtls_x509_signature_observer observer, void* observer_context)
{
    mbedtls_x509_crt* chain[MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE];
    mbedtls_x509_crt* child;
    mbedtls_x509_crt* parent;
    unsigned length = 0;
    unsigned self_count = 0;
    unsigned i;
    int child_is_trusted = 0;
    int parent_is_trusted;

    if (flags == NULL) return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    *flags = 0;
    if (crt == NULL || profile == NULL) {
        *flags = (uint32_t) -1;
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    /* Mirror the public upstream wrapper's end-entity checks. With no mutable
     * callback, any failure is final and needs no expensive signature work.
     */
    if (cn != NULL) x509_crt_verify_name(crt, cn, flags);
    if (mbedtls_x509_profile_check_pk_alg(profile, mbedtls_pk_get_type(&crt->pk)) != 0)
        *flags |= MBEDTLS_X509_BADCERT_BAD_PK;
    if (x509_profile_check_key(profile, &crt->pk) != 0)
        *flags |= MBEDTLS_X509_BADCERT_BAD_KEY;
    if (*flags != 0) return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;

    child = crt;
    for (;;) {
        if (length >= MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE) {
            *flags = (uint32_t) -1;
            return MBEDTLS_ERR_X509_FATAL_ERROR;
        }
        chain[length++] = child;

        /* A trust anchor's own signature is not verified by upstream. Its
         * child's signature was already verified while selecting this root.
         */
        if (child_is_trusted) break;

        if (mbedtls_x509_profile_check_md_alg(profile, child->sig_md) != 0)
            *flags |= MBEDTLS_X509_BADCERT_BAD_MD;
        if (mbedtls_x509_profile_check_pk_alg(profile, child->sig_pk) != 0)
            *flags |= MBEDTLS_X509_BADCERT_BAD_PK;
        if (*flags != 0) return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;

        /* Keep the upstream trusted-EE exception exactly: self-issued and an
         * exact DER match in the fixed root store, not merely self-signed.
         */
        if (length == 1 && x509_crt_check_ee_locally_trusted(child, trust_ca) == 0)
            return 0;

        parent = NULL;
        parent_is_trusted = 0;

        /* Roots have priority at EVERY level. For roots only, suitability
         * includes a correct child signature. A failed candidate must not
         * hide a later matching-name root with the correct key.
         */
        for (parent = trust_ca; parent != NULL; parent = parent->next) {
            if (!connectcoin_x509_parent_matches(child, parent, 1, length - 1, self_count))
                continue;
            if (connectcoin_x509_check_signature(child, parent, observer, observer_context) != 0)
                continue;
            parent_is_trusted = 1;
            break;
        }
        if (parent == NULL) {
            for (parent = child->next; parent != NULL; parent = parent->next) {
                if (connectcoin_x509_parent_matches(child, parent, 0, length - 1, self_count))
                    break;
            }
        }
        if (parent == NULL) {
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        }

        /* Preserve the upstream order: count this self-issued intermediate
         * only AFTER parent selection, not in that selection's pathlen test.
         */
        if (length != 1 && x509_name_cmp(&child->issuer, &child->subject) == 0)
            ++self_count;
        if (!parent_is_trusted && length > MBEDTLS_X509_MAX_INTERMEDIATE_CA) {
            *flags = (uint32_t) -1;
            return MBEDTLS_ERR_X509_FATAL_ERROR;
        }
        if (x509_profile_check_key(profile, &parent->pk) != 0) {
            *flags |= MBEDTLS_X509_BADCERT_BAD_KEY;
            return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        }

        child = parent;
        child_is_trusted = parent_is_trusted;
    }

    /* The final edge to chain[length - 1] (trusted root) was checked during
     * selection. Verify only the deferred edges, highest intermediate first.
     * length >= 2 here; trusted end entities already returned above.
     */
    for (i = length - 2; i > 0; --i) {
        if (connectcoin_x509_check_signature(chain[i - 1], chain[i], observer, observer_context) != 0) {
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        }
    }
    return 0;
}
