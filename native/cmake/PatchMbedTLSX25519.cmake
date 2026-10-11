# Copyright (c) 2026 The ConnectCoin developers. MIT license.
# Keep PSA's original key decoders, group checks, scalar validation and public
# point rejection. Replace only the two Curve25519 multiplications used by TLS.
# The helper from the RSA-PSS patch rejects unexpected/partially patched input.
if(NOT DEFINED MBEDTLS_SOURCE_DIR OR NOT COMMAND p2c_mbedtls_replace)
  message(FATAL_ERROR "Load the pinned Mbed TLS checked replacement helper first")
endif()

# Several replacements retain their upstream needle in the fallback branch.
# A changed adapter must therefore reject a stale applied block before the
# generic helper can accidentally match that retained needle a second time.
function(p2c_x25519_replace relative_path old_text new_text marker)
  file(READ "${MBEDTLS_SOURCE_DIR}/${relative_path}" contents)
  p2c_mbedtls_count("${contents}" "${marker}" marker_count)
  p2c_mbedtls_count("${contents}" "${new_text}" current_count)
  if(current_count EQUAL 1 AND marker_count EQUAL 1)
    return()
  endif()
  if(NOT marker_count EQUAL 0 OR NOT current_count EQUAL 0)
    message(FATAL_ERROR "P2C X25519 patch: ${relative_path} has a stale, partial or duplicate adapter; use a fresh pinned dependency checkout")
  endif()
  p2c_mbedtls_replace("${relative_path}" "${old_text}" "${new_text}" 1)
endfunction()

p2c_x25519_replace(library/psa_crypto_ecp.c [=[#include "psa_crypto_ecp.h"]=]
[=[#include "psa_crypto_ecp.h"
#include "mbedtls_x25519.h"]=] [=[#include "mbedtls_x25519.h"]=])

# Compile only the existing HACL primitive, without enabling Everest's broader
# ECDH-context variant or changing the generic reference implementation.
p2c_x25519_replace(3rdparty/everest/library/Hacl_Curve25519_joined.c
[=[#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)]=]
[=[#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED) || defined(CONNECTCOIN_X25519_ACCELERATION)]=]
[=[|| defined(CONNECTCOIN_X25519_ACCELERATION)]=])

p2c_x25519_replace(library/psa_crypto_ecp.c
[=[    status = mbedtls_psa_ecp_export_key(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(
            PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->type)),
        ecp, data, data_size, data_length);]=]
[=[#if defined(CONNECTCOIN_X25519_ACCELERATION)
    /* The original load_representation above already validated the private
     * key. Public-key input and every other curve retain the original path. */
    if (ecp->grp.id == MBEDTLS_ECP_DP_CURVE25519 &&
        PSA_KEY_TYPE_IS_KEY_PAIR(attributes->type)) {
        status = mbedtls_to_psa_error(connectcoin_mbedtls_x25519_mul_keypair(
            ecp, &ecp->grp.G, data, data_size, data_length));
    } else
#endif
    {
        status = mbedtls_psa_ecp_export_key(
            PSA_KEY_TYPE_ECC_PUBLIC_KEY(
                PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->type)),
            ecp, data, data_size, data_length);
    }]=] [=[/* The original load_representation above already validated the private]=])

p2c_x25519_replace(library/psa_crypto_ecp.c
[=[    status = mbedtls_to_psa_error(
        mbedtls_ecdh_get_params(&ecdh, their_key, MBEDTLS_ECDH_THEIRS));]=]
[=[#if defined(CONNECTCOIN_X25519_ACCELERATION)
    /* Both original load_representation calls have succeeded, including the
     * peer-point checks. Serialize those validated values; keep exit wiping. */
    if (ecp->grp.id == MBEDTLS_ECP_DP_CURVE25519) {
        status = mbedtls_to_psa_error(connectcoin_mbedtls_x25519_mul_keypair(
            ecp, &their_key->Q, shared_secret, shared_secret_size,
            shared_secret_length));
        if (status == PSA_SUCCESS && PSA_BITS_TO_BYTES(bits) != *shared_secret_length) {
            status = PSA_ERROR_CORRUPTION_DETECTED;
        }
        goto exit;
    }
#endif
    status = mbedtls_to_psa_error(
        mbedtls_ecdh_get_params(&ecdh, their_key, MBEDTLS_ECDH_THEIRS));]=]
[=[/* Both original load_representation calls have succeeded, including the]=])
