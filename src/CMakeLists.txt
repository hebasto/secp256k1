# Must be included before CMAKE_INSTALL_INCLUDEDIR is used.
include(GNUInstallDirs)
set(${PROJECT_NAME}_installables "")

add_library(internal_obj OBJECT "")
target_sources(internal_obj PRIVATE
  precomputed_ecmult.c
  precomputed_ecmult_gen.c
)

add_library(${PROJECT_NAME} SHARED "")
target_sources(${PROJECT_NAME} PRIVATE
  secp256k1.c
  $<TARGET_OBJECTS:internal_obj>
)
target_include_directories(${PROJECT_NAME}
  INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
if(WIN32)
  target_compile_definitions(${PROJECT_NAME} PRIVATE DLL_EXPORT)
endif()
set_target_properties(${PROJECT_NAME} PROPERTIES
  VERSION "${${PROJECT_NAME}_LIB_VERSION_CURRENT}.${${PROJECT_NAME}_LIB_VERSION_AGE}.${${PROJECT_NAME}_LIB_VERSION_REVISION}"
  SOVERSION "${${PROJECT_NAME}_LIB_VERSION_CURRENT}"
)
if(SECP256K1_BUILD_SHARED)
  list(APPEND ${PROJECT_NAME}_installables ${PROJECT_NAME})
else()
  set_target_properties(${PROJECT_NAME} PROPERTIES
    EXCLUDE_FROM_ALL TRUE
  )
endif()

add_library(${PROJECT_NAME}_static STATIC "")
target_sources(${PROJECT_NAME}_static PRIVATE
  secp256k1.c
  $<TARGET_OBJECTS:internal_obj>
)
target_include_directories(${PROJECT_NAME}_static
  INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
if(NOT MSVC)
  set_target_properties(${PROJECT_NAME}_static PROPERTIES
    OUTPUT_NAME ${PROJECT_NAME}
  )
endif()
if(SECP256K1_BUILD_STATIC)
  list(APPEND ${PROJECT_NAME}_installables ${PROJECT_NAME}_static)
else()
  set_target_properties(${PROJECT_NAME}_static PROPERTIES
    EXCLUDE_FROM_ALL TRUE
  )
endif()

add_library(binary_interface INTERFACE)
target_compile_definitions(binary_interface INTERFACE
  $<$<C_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
)

add_library(link_library INTERFACE)
if(SECP256K1_BUILD_SHARED)
  target_link_libraries(link_library INTERFACE ${PROJECT_NAME})
endif()
if(SECP256K1_BUILD_STATIC)
  target_link_libraries(link_library INTERFACE ${PROJECT_NAME}_static)
endif()

if(SECP256K1_BUILD_BENCHMARK)
  add_executable(bench bench.c)
  target_link_libraries(bench binary_interface link_library)

  add_executable(bench_internal bench_internal.c $<TARGET_OBJECTS:internal_obj>)
  target_link_libraries(bench_internal binary_interface)
  add_executable(bench_ecmult bench_ecmult.c $<TARGET_OBJECTS:internal_obj>)
  target_link_libraries(bench_ecmult binary_interface)
endif()

if(SECP256K1_BUILD_TESTS)
  add_executable(noverify_tests tests.c $<TARGET_OBJECTS:internal_obj>)
  target_link_libraries(noverify_tests binary_interface)
  add_test(noverify_tests noverify_tests)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Coverage")
    add_executable(tests tests.c $<TARGET_OBJECTS:internal_obj>)
    target_link_libraries(tests binary_interface)
    target_compile_definitions(tests PRIVATE VERIFY)
    add_test(tests tests)
  endif()
endif()

if(SECP256K1_BUILD_CTIME_TESTS)
  add_executable(ctime_tests ctime_tests.c)
  target_link_libraries(ctime_tests binary_interface link_library)
  add_test(ctime_tests ctime_tests)
endif()

if(SECP256K1_BUILD_EXHAUSTIVE_TESTS)
  add_executable(exhaustive_tests tests_exhaustive.c $<TARGET_OBJECTS:internal_obj>)
  target_link_libraries(exhaustive_tests binary_interface)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Coverage")
    target_compile_definitions(exhaustive_tests PRIVATE VERIFY)
  endif()
  add_test(exhaustive_tests exhaustive_tests)
endif()

install(TARGETS ${${PROJECT_NAME}_installables}
  EXPORT ${PROJECT_NAME}Targets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
set(${PROJECT_NAME}_headers
  "${PROJECT_SOURCE_DIR}/include/secp256k1.h"
  "${PROJECT_SOURCE_DIR}/include/secp256k1_preallocated.h"
)
if(SECP256K1_ENABLE_MODULE_ECDH)
  list(APPEND ${PROJECT_NAME}_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_ecdh.h")
endif()
if(SECP256K1_ENABLE_MODULE_RECOVERY)
  list(APPEND ${PROJECT_NAME}_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_recovery.h")
endif()
if(SECP256K1_ENABLE_MODULE_EXTRAKEYS)
  list(APPEND ${PROJECT_NAME}_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_extrakeys.h")
endif()
if(SECP256K1_ENABLE_MODULE_SCHNORRSIG)
  list(APPEND ${PROJECT_NAME}_headers "${PROJECT_SOURCE_DIR}/include/secp256k1_schnorrsig.h")
endif()
install(FILES ${${PROJECT_NAME}_headers}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT ${PROJECT_NAME}Targets
  FILE ${PROJECT_NAME}Targets.cmake
  NAMESPACE ${PROJECT_NAME}::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

include(CMakePackageConfigHelpers)
configure_package_config_file("${PROJECT_SOURCE_DIR}/cmake/Config.cmake.in"
  "${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)
write_basic_package_version_file("${PROJECT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
  COMPATIBILITY SameMajorVersion
)
install(FILES
          "${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
          "${PROJECT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)
