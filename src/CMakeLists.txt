# Copyright 2022 Hennadii Stepanov
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

add_library(secp256k1 "")
target_sources(secp256k1
  PRIVATE
    secp256k1.c
    precomputed_ecmult.c
    precomputed_ecmult_gen.c
)

if(BUILD_BENCHMARK)
  add_executable(bench bench.c)
  target_link_libraries(bench PRIVATE secp256k1)
  add_executable(bench_internal bench_internal.c)
  target_link_libraries(bench_internal PRIVATE secp256k1)
  add_executable(bench_ecmult bench_ecmult.c)
  target_link_libraries(bench_ecmult PRIVATE secp256k1)
endif()

if(BUILD_TESTS)
  add_executable(tests tests.c)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Coverage")
    target_compile_definitions(tests PRIVATE -DVERIFY)
  endif()
  target_link_libraries(tests PRIVATE secp256k1)
  target_link_options(tests
    PRIVATE
      $<$<NOT:$<PLATFORM_ID:Darwin>>:-static>
  )
endif()

if(BUILD_EXHAUSTIVE_TESTS)
  add_executable(exhaustive_tests tests_exhaustive.c)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Coverage")
    target_compile_definitions(exhaustive_tests PRIVATE -DVERIFY)
  endif()
  target_link_libraries(exhaustive_tests PRIVATE secp256k1)
  target_link_options(exhaustive_tests
    PRIVATE
      $<$<NOT:$<PLATFORM_ID:Darwin>>:-static>
  )
endif()

include(GNUInstallDirs)
install(
  TARGETS secp256k1
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
set(secp_headers
  "${PROJECT_SOURCE_DIR}/include/secp256k1.h"
  "${PROJECT_SOURCE_DIR}/include/secp256k1_preallocated.h"
)
if(ENABLE_MODULE_ECDH)
  list(APPEND secp_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_ecdh.h")
endif()
if(ENABLE_MODULE_RECOVERY)
  list(APPEND secp_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_recovery.h")
endif()
if(ENABLE_MODULE_EXTRAKEYS)
  list(APPEND secp_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_extrakeys.h")
endif()
if(ENABLE_MODULE_SCHNORRSIG)
  list(APPEND secp_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_schnorrsig.h")
endif()
install(
  FILES ${secp_headers}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
