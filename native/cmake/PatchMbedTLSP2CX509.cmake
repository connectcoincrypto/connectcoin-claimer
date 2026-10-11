# Copyright (c) 2026 The ConnectCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Include a narrow opt-in verifier after all private X.509 helpers in pinned
# Mbed TLS 3.6.7. The existing entry points remain unchanged. Use the checked,
# idempotent replacement helper loaded by PatchMbedTLSP2CRSAPSS.cmake first.
if(NOT DEFINED MBEDTLS_SOURCE_DIR)
  message(FATAL_ERROR "MBEDTLS_SOURCE_DIR is required")
endif()
if(NOT COMMAND p2c_mbedtls_replace)
  message(FATAL_ERROR "The checked P2C Mbed TLS replacement helper must be loaded first")
endif()

set(p2c_x509_original_end [=[
#endif /* MBEDTLS_X509_CRT_PARSE_C */
]=])
set(p2c_x509_patched_end [=[
/* ConnectCoin: separate clockless root-first entry point, not a legacy change. */
#include "mbedtls_x509_root_first.c"

#endif /* MBEDTLS_X509_CRT_PARSE_C */
]=])

# Require the exact final guard (with only whitespace following it), even on
# already-patched trees. An upstream layout change needs an explicit review.
file(READ "${MBEDTLS_SOURCE_DIR}/library/x509_crt.c" p2c_x509_contents)
string(STRIP "${p2c_x509_contents}" p2c_x509_stripped)
string(LENGTH "${p2c_x509_stripped}" p2c_x509_length)
string(STRIP "${p2c_x509_original_end}" p2c_x509_guard)
string(LENGTH "${p2c_x509_guard}" p2c_x509_guard_length)
p2c_mbedtls_count("${p2c_x509_contents}" "${p2c_x509_guard}" p2c_x509_guard_count)
if(NOT p2c_x509_guard_count EQUAL 1)
  message(FATAL_ERROR "P2C X.509 patch: expected exactly one final source guard")
endif()
p2c_mbedtls_count("${p2c_x509_contents}" "#include \"mbedtls_x509_root_first.c\"" p2c_x509_include_count)
p2c_mbedtls_count("${p2c_x509_contents}" "${p2c_x509_patched_end}" p2c_x509_patched_count)
if(NOT p2c_x509_include_count EQUAL 0)
  if(NOT p2c_x509_include_count EQUAL 1 OR NOT p2c_x509_patched_count EQUAL 1)
    message(FATAL_ERROR "P2C X.509 patch: partial or duplicate adapter include")
  endif()
endif()
if(p2c_x509_length LESS p2c_x509_guard_length)
  message(FATAL_ERROR "P2C X.509 patch: unexpected pinned source ending")
endif()
math(EXPR p2c_x509_guard_position "${p2c_x509_length} - ${p2c_x509_guard_length}")
string(SUBSTRING "${p2c_x509_stripped}" ${p2c_x509_guard_position} -1 p2c_x509_ending)
if(NOT p2c_x509_ending STREQUAL p2c_x509_guard)
  message(FATAL_ERROR "P2C X.509 patch: final source guard changed; review the pinned dependency")
endif()

p2c_mbedtls_replace(library/x509_crt.c
  "${p2c_x509_original_end}" "${p2c_x509_patched_end}" 1)

unset(p2c_x509_original_end)
unset(p2c_x509_patched_end)
unset(p2c_x509_contents)
unset(p2c_x509_stripped)
unset(p2c_x509_length)
unset(p2c_x509_guard)
unset(p2c_x509_guard_length)
unset(p2c_x509_guard_count)
unset(p2c_x509_include_count)
unset(p2c_x509_patched_count)
unset(p2c_x509_guard_position)
unset(p2c_x509_ending)
