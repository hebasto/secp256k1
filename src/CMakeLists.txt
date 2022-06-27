add_library(secp256k1 "")
target_sources(secp256k1
  PRIVATE
    secp256k1.c
    precomputed_ecmult.c
    precomputed_ecmult_gen.c
)

if(BUILD_BENCHMARK OR BUILD_TESTS OR BUILD_EXHAUSTIVE_TESTS)
  add_library(bench_or_test_binary INTERFACE)
  target_compile_definitions(bench_or_test_binary INTERFACE
    $<$<C_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
  )
  target_link_libraries(bench_or_test_binary INTERFACE
    secp256k1
  )
endif()

if(BUILD_BENCHMARK)
  add_executable(bench bench.c)
  target_link_libraries(bench bench_or_test_binary)
  add_executable(bench_internal bench_internal.c)
  target_link_libraries(bench_internal bench_or_test_binary)
  add_executable(bench_ecmult bench_ecmult.c)
  target_link_libraries(bench_ecmult bench_or_test_binary)
endif()

if(BUILD_TESTS)
  add_executable(tests tests.c)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Coverage")
    target_compile_definitions(tests PRIVATE -DVERIFY)
  endif()
  target_link_libraries(tests bench_or_test_binary)
  add_test(tests tests)
endif()

if(BUILD_EXHAUSTIVE_TESTS)
  add_executable(exhaustive_tests tests_exhaustive.c)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Coverage")
    target_compile_definitions(exhaustive_tests PRIVATE -DVERIFY)
  endif()
  target_link_libraries(exhaustive_tests bench_or_test_binary)
  add_test(exhaustive_tests exhaustive_tests)
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
