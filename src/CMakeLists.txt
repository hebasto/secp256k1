if(CMAKE_VERSION VERSION_GREATER 3.2)
  # Honor visibility properties for all target types.
  # See: https://cmake.org/cmake/help/latest/policy/CMP0063.html
  cmake_policy(SET CMP0063 NEW)
endif()

add_library(secp256k1_precomputed STATIC "")
target_sources(secp256k1_precomputed PRIVATE
  precomputed_ecmult.c
  precomputed_ecmult_gen.c
)

add_library(secp256k1 SHARED "")
target_sources(secp256k1 PRIVATE
  secp256k1.c
)
set_target_properties(secp256k1 PROPERTIES
  C_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN TRUE
  VERSION "${secp256k1_LIB_VERSION_CURRENT}.${secp256k1_LIB_VERSION_REVISION}.${secp256k1_LIB_VERSION_AGE}"
  SOVERSION "${secp256k1_LIB_VERSION_CURRENT}"
)

add_library(secp256k1_static STATIC "")
target_sources(secp256k1_static PRIVATE
  secp256k1.c
)
set_target_properties(secp256k1_static PROPERTIES
  OUTPUT_NAME secp256k1
)

if(SECP_BUILD_BENCHMARK OR SECP_BUILD_TESTS OR SECP_BUILD_EXHAUSTIVE_TESTS)
  add_library(bench_or_test_binary INTERFACE)
  target_compile_definitions(bench_or_test_binary INTERFACE
    $<$<C_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
  )
  target_link_libraries(bench_or_test_binary INTERFACE
    secp256k1
    secp256k1_precomputed
  )
endif()

if(SECP_BUILD_BENCHMARK)
  add_executable(bench bench.c)
  target_link_libraries(bench bench_or_test_binary)
  add_executable(bench_internal bench_internal.c)
  target_link_libraries(bench_internal bench_or_test_binary)
  add_executable(bench_ecmult bench_ecmult.c)
  target_link_libraries(bench_ecmult bench_or_test_binary)
endif()

if(SECP_BUILD_TESTS)
  add_executable(tests tests.c)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Coverage")
    target_compile_definitions(tests PRIVATE -DVERIFY)
  endif()
  target_link_libraries(tests bench_or_test_binary)
  add_test(tests tests)
endif()

if(SECP_BUILD_EXHAUSTIVE_TESTS)
  add_executable(exhaustive_tests tests_exhaustive.c)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Coverage")
    target_compile_definitions(exhaustive_tests PRIVATE -DVERIFY)
  endif()
  target_link_libraries(exhaustive_tests bench_or_test_binary)
  add_test(exhaustive_tests exhaustive_tests)
endif()

include(GNUInstallDirs)
install(
  TARGETS secp256k1 secp256k1_static
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
set(secp_headers
  "${PROJECT_SOURCE_DIR}/include/secp256k1.h"
  "${PROJECT_SOURCE_DIR}/include/secp256k1_preallocated.h"
)
if(SECP_ENABLE_MODULE_ECDH)
  list(APPEND secp_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_ecdh.h")
endif()
if(SECP_ENABLE_MODULE_RECOVERY)
  list(APPEND secp_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_recovery.h")
endif()
if(SECP_ENABLE_MODULE_EXTRAKEYS)
  list(APPEND secp_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_extrakeys.h")
endif()
if(SECP_ENABLE_MODULE_SCHNORRSIG)
  list(APPEND secp_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_schnorrsig.h")
endif()
install(
  FILES ${secp_headers}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
