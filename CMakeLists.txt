cmake_minimum_required(VERSION 3.1)
if(CMAKE_VERSION VERSION_GREATER 3.14)
  # MSVC warning flags are not in CMAKE_<LANG>_FLAGS by default.
  # See: https://cmake.org/cmake/help/latest/policy/CMP0092.html
  cmake_policy(SET CMP0092 NEW)
endif()
project(secp256k1 VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 90)
set(CMAKE_C_EXTENSIONS OFF)

option(BUILD_BENCHMARK "Build benchmarks." ON)
option(BUILD_TESTS "Build tests." ON)
option(BUILD_EXHAUSTIVE_TESTS "Build exhaustive tests." ON)
option(BUILD_EXAMPLES "Build examples." OFF)

option(ENABLE_MODULE_ECDH "Enable ECDH module." OFF)
if(ENABLE_MODULE_ECDH)
  add_definitions(-DENABLE_MODULE_ECDH)
endif()

option(ENABLE_MODULE_RECOVERY "Enable ECDSA pubkey recovery module." OFF)
if(ENABLE_MODULE_RECOVERY)
  add_definitions(-DENABLE_MODULE_RECOVERY)
endif()

option(ENABLE_MODULE_EXTRAKEYS "Enable extrakeys module." OFF)
option(ENABLE_MODULE_SCHNORRSIG "Enable schnorrsig module." OFF)
if(ENABLE_MODULE_SCHNORRSIG)
  set(ENABLE_MODULE_EXTRAKEYS ON)
  add_definitions(-DENABLE_MODULE_SCHNORRSIG)
endif()
if(ENABLE_MODULE_EXTRAKEYS)
  add_definitions(-DENABLE_MODULE_EXTRAKEYS)
endif()

option(ENABLE_EXPERIMENTAL "Enable experimental configure options." OFF)
option(USE_EXTERNAL_DEFAULT_CALLBACKS "Enable external default callback functions." OFF)
if(USE_EXTERNAL_DEFAULT_CALLBACKS)
  add_definitions(-DUSE_EXTERNAL_DEFAULT_CALLBACKS)
endif()

set(ECMULT_WINDOW_SIZE auto CACHE STRING "Window size for ecmult precomputation for verification, specified as integer in range [2..24]. \"auto\" is a reasonable setting for desktop machines (currently 15). [default=auto]")
if(ECMULT_WINDOW_SIZE STREQUAL "auto")
  set(ECMULT_WINDOW_SIZE 15)
endif()
if(NOT ECMULT_WINDOW_SIZE MATCHES ^[1-9][0-9]*$ OR ECMULT_WINDOW_SIZE LESS 2 OR ECMULT_WINDOW_SIZE GREATER 24)
  message(FATAL_ERROR "ECMULT_WINDOW_SIZE value is \"${ECMULT_WINDOW_SIZE}\", but must an integer in range [2..24] or \"auto\".")
endif()
add_definitions(-DECMULT_WINDOW_SIZE=${ECMULT_WINDOW_SIZE})

set(ECMULT_GEN_PREC_BITS auto CACHE STRING "Precision bits to tune the precomputed table size for signing, specified as integer 2, 4 or 8. \"auto\" is a reasonable setting for desktop machines (currently 4). [default=auto]")
set_property(CACHE ECMULT_GEN_PREC_BITS PROPERTY STRINGS auto 2 4 8)
if(ECMULT_GEN_PREC_BITS STREQUAL "auto")
  set(ECMULT_GEN_PREC_BITS 4)
endif()
if(NOT ECMULT_GEN_PREC_BITS STREQUAL 2 AND NOT ECMULT_GEN_PREC_BITS STREQUAL 4 AND NOT ECMULT_GEN_PREC_BITS STREQUAL 8)
  message(FATAL_ERROR "ECMULT_GEN_PREC_BITS value is \"${ECMULT_GEN_PREC_BITS}\", but must an integer 2, 4, 8, or \"auto\".")
endif()
add_definitions(-DECMULT_GEN_PREC_BITS=${ECMULT_GEN_PREC_BITS})

option(USE_FORCE_WIDEMUL_INT128 "Force the use of the (unsigned) __int128 based wide multiplication implementation." OFF)
if(USE_FORCE_WIDEMUL_INT128)
  add_definitions(-DUSE_FORCE_WIDEMUL_INT128)
endif()
option(USE_FORCE_WIDEMUL_INT64 "Force the use of the (u)int64_t based wide multiplication implementation." OFF)
if(USE_FORCE_WIDEMUL_INT64)
  add_definitions(-DUSE_FORCE_WIDEMUL_INT64)
endif()
if(USE_FORCE_WIDEMUL_INT128 AND USE_FORCE_WIDEMUL_INT64)
  message(FATAL_ERROR "USE_FORCE_WIDEMUL_INT128 and USE_FORCE_WIDEMUL_INT64 cannot be enabled simultaneously.")
endif()

mark_as_advanced(FORCE
  USE_FORCE_WIDEMUL_INT128
  USE_FORCE_WIDEMUL_INT64
)

# Define custom "RelWithAsserts" build type
set(CMAKE_C_FLAGS_RELWITHASSERTS "-O2 -g" CACHE STRING
  "Flags used by the C compiler during \"RelWithAsserts\" builds."
  FORCE
)
# Define custom "Coverage" build type
set(CMAKE_C_FLAGS_COVERAGE "-O0 --coverage -Wno-unused-parameter" CACHE STRING
  "Flags used by the C compiler during \"Coverage\" builds."
  FORCE
)
set(CMAKE_EXE_LINKER_FLAGS_COVERAGE "--coverage" CACHE STRING
  "Flags used for linking binaries during \"Coverage\" builds."
  FORCE
)
set(CMAKE_SHARED_LINKER_FLAGS_COVERAGE "--coverage" CACHE STRING
  "Flags used by the shared libraries linker during \"Coverage\" builds."
  FORCE
)
mark_as_advanced(
  CMAKE_C_FLAGS_RELWITHASSERTS
  CMAKE_C_FLAGS_COVERAGE
  CMAKE_EXE_LINKER_FLAGS_COVERAGE
  CMAKE_SHARED_LINKER_FLAGS_COVERAGE
)
get_property(cached_cmake_build_type CACHE CMAKE_BUILD_TYPE PROPERTY TYPE)
if(cached_cmake_build_type)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
    STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo" "RelWithAsserts" "Coverage"
  )
endif()
set(default_build_type "RelWithAsserts")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to \"${default_build_type}\" as none was specified")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
  add_definitions(-DCOVERAGE)
endif()

include(cmake/TryAddCompileOption.cmake)
if(MSVC)
  try_add_compile_option(/W3)
  try_add_compile_option(/wd4146)
  try_add_compile_option(/wd4244)
  try_add_compile_option(/wd4267)
  try_add_compile_option(/wd4334)
else()
  try_add_compile_option(-pedantic)
  try_add_compile_option(-Wall)
  try_add_compile_option(-Wcast-align)
  try_add_compile_option(-Wcast-align=strict)
  try_add_compile_option(-Wconditional-uninitialized)
  try_add_compile_option(-Wextra)
  try_add_compile_option(-Wnested-externs)
  try_add_compile_option(-Wno-long-long)
  try_add_compile_option(-Wno-overlength-strings)
  try_add_compile_option(-Wno-unused-function)
  try_add_compile_option(-Wshadow)
  try_add_compile_option(-Wstrict-prototypes)
  try_add_compile_option(-Wundef)
endif()

if(CMAKE_VERSION VERSION_GREATER 3.2)
  # Honor visibility properties for all target types.
  # See: https://cmake.org/cmake/help/latest/policy/CMP0063.html
  cmake_policy(SET CMP0063 NEW)
endif()
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

include(CTest)
if(BUILD_BENCHMARK OR BUILD_TESTS OR BUILD_EXHAUSTIVE_TESTS OR BUILD_EXAMPLES)
  # We do not use CMake CTest's BUILD_TESTING option.
  enable_testing()
endif()

add_subdirectory(src)
if(BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

message("\n")
message("Configure summary")
message("=================")
message("Optional modules:")
message("  ECDH ............................. ${ENABLE_MODULE_ECDH}")
message("  ECDSA pubkey recovery ............ ${ENABLE_MODULE_RECOVERY}")
message("  extrakeys ........................ ${ENABLE_MODULE_EXTRAKEYS}")
message("  schnorrsig ....................... ${ENABLE_MODULE_SCHNORRSIG}")
message("Parameters:")
message("  ecmult window size ............... ${ECMULT_WINDOW_SIZE}")
message("  ecmult gen precision bits ........ ${ECMULT_GEN_PREC_BITS}")
message("Optional features:")
message("  external callbacks ............... ${USE_EXTERNAL_DEFAULT_CALLBACKS}")
if(USE_FORCE_WIDEMUL_INT128)
  message("  override wide multiplication ..... int128")
endif()
if(USE_FORCE_WIDEMUL_INT64)
  message("  override wide multiplication ..... int64")
endif()
message("Optional binaries:")
message("  benchmark ........................ ${BUILD_BENCHMARK}")
message("  tests ............................ ${BUILD_TESTS}")
message("  exhaustive tests ................. ${BUILD_EXHAUSTIVE_TESTS}")
message("  examples ......................... ${BUILD_EXAMPLES}")
message("")
if(CMAKE_CROSSCOMPILING)
  message("Cross compiling for ................ ${CMAKE_SYSTEM_NAME}, ${CMAKE_SYSTEM_PROCESSOR}")
endif()
get_directory_property(definitions COMPILE_DEFINITIONS)
message("Preprocessor defined macros ........ ${definitions}")
message("C compiler ......................... ${CMAKE_C_COMPILER_LAUNCHER} ${CMAKE_C_COMPILER}")
message("CFLAGS ............................. ${CMAKE_C_FLAGS}")
get_directory_property(compile_options COMPILE_OPTIONS)
string(REPLACE ";" " " compile_options "${compile_options}")
message("Compile options .................... " ${compile_options})
if(DEFINED CMAKE_BUILD_TYPE)
  message("Build type:")
  message(" - configuration ................... ${CMAKE_BUILD_TYPE}")
  string(TOUPPER ${CMAKE_BUILD_TYPE} build_type)
  message(" - CFLAGS .......................... ${CMAKE_C_FLAGS_${build_type}}")
  message(" - LDFLAGS for executables ......... ${CMAKE_EXE_LINKER_FLAGS_${build_type}}")
  message(" - LDFLAGS for shared libraries .... ${CMAKE_SHARED_LINKER_FLAGS_${build_type}}")
else()
  message("Available configurations ........... ${CMAKE_CONFIGURATION_TYPES}")
endif()
message("\n")
