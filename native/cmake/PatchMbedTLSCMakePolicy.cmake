# Copyright (c) 2026 The ConnectCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

if(NOT DEFINED MBEDTLS_SOURCE_DIR)
  message(FATAL_ERROR "MBEDTLS_SOURCE_DIR is required")
endif()

set(mbedtls_cmakelists "${MBEDTLS_SOURCE_DIR}/CMakeLists.txt")
file(READ "${mbedtls_cmakelists}" mbedtls_cmake_contents)

set(mbedtls_old_minimum "cmake_minimum_required(VERSION 3.5.1)")
set(mbedtls_new_minimum "cmake_minimum_required(VERSION 3.10.2)")
string(FIND "${mbedtls_cmake_contents}" "${mbedtls_new_minimum}" mbedtls_new_minimum_position)
if(mbedtls_new_minimum_position EQUAL -1)
  string(FIND "${mbedtls_cmake_contents}" "${mbedtls_old_minimum}" mbedtls_old_minimum_position)
  if(mbedtls_old_minimum_position EQUAL -1)
    message(FATAL_ERROR "Mbed TLS's CMake minimum declaration changed unexpectedly")
  endif()
  string(REPLACE "${mbedtls_old_minimum}" "${mbedtls_new_minimum}"
    mbedtls_cmake_contents "${mbedtls_cmake_contents}"
  )
  file(WRITE "${mbedtls_cmakelists}" "${mbedtls_cmake_contents}")
endif()
