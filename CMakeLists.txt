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

option(ALLOW_EXPERIMENTAL "Allow experimental configure options." OFF)
option(USE_EXTERNAL_DEFAULT_CALLBACKS "Enable external default callback functions." OFF)
if(USE_EXTERNAL_DEFAULT_CALLBACKS)
  add_definitions(-DUSE_EXTERNAL_DEFAULT_CALLBACKS)
endif()

set(ECMULT_WINDOW_SIZE auto CACHE STRING "Window size for ecmult precomputation for verification, specified as integer in range [2..24]. \"auto\" is a reasonable setting for desktop machines (currently 15). [default=auto]")
if(ECMULT_WINDOW_SIZE STREQUAL auto)
  set(ECMULT_WINDOW_SIZE 15)
endif()
if(NOT ECMULT_WINDOW_SIZE MATCHES ^[1-9][0-9]*$ OR ECMULT_WINDOW_SIZE LESS 2 OR ECMULT_WINDOW_SIZE GREATER 24)
  message(FATAL_ERROR "ECMULT_WINDOW_SIZE value is \"${ECMULT_WINDOW_SIZE}\", but must an integer in range [2..24] or \"auto\".")
endif()
add_definitions(-DECMULT_WINDOW_SIZE=${ECMULT_WINDOW_SIZE})

set(ECMULT_GEN_PREC_BITS auto CACHE STRING "Precision bits to tune the precomputed table size for signing, specified as integer 2, 4 or 8. \"auto\" is a reasonable setting for desktop machines (currently 4). [default=auto]")
set_property(CACHE ECMULT_GEN_PREC_BITS PROPERTY STRINGS auto 2 4 8)
if(ECMULT_GEN_PREC_BITS STREQUAL auto)
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
set(CMAKE_C_FLAGS_COVERAGE "-O0 --coverage" CACHE STRING
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
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
  STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo" "RelWithAsserts" "Coverage"
)
set(default_build_type "RelWithAsserts")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to \"${default_build_type}\" as none was specified")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
  add_definitions(-DCOVERAGE)
endif()

include(cmake/secp_try_append_cflag.cmake)
secp_try_append_cflag(-pedantic)
secp_try_append_cflag(-Wno-long-long)
secp_try_append_cflag(-Wnested-externs)
secp_try_append_cflag(-Wshadow)
secp_try_append_cflag(-Wstrict-prototypes)
secp_try_append_cflag(-Wundef)
secp_try_append_cflag(-Wno-overlength-strings)
secp_try_append_cflag(-Wall)
secp_try_append_cflag(-Wno-unused-function)
secp_try_append_cflag(-Wextra)
secp_try_append_cflag(-Wcast-align)
secp_try_append_cflag(-Wcast-align=strict)
secp_try_append_cflag(-Wconditional-uninitialized)

if(CMAKE_VERSION VERSION_GREATER 3.2)
  # Honor visibility properties for all target types.
  # See: https://cmake.org/cmake/help/latest/policy/CMP0063.html
  cmake_policy(SET CMP0063 NEW)
endif()
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

add_subdirectory(src)
if(BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

message("\n")
message("Configure summary")
message("=================")
if(CMAKE_CROSSCOMPILING)
  message("Cross compiling for ${CMAKE_SYSTEM_NAME}, ${CMAKE_SYSTEM_PROCESSOR}")
endif()
message("Build type ......................... ${CMAKE_BUILD_TYPE}")
message("Optional binaries:")
message("  benchmark ........................ ${BUILD_BENCHMARK}")
message("  tests ............................ ${BUILD_TESTS}")
message("  exhaustive tests ................. ${BUILD_EXHAUSTIVE_TESTS}")
message("  examples ......................... ${BUILD_EXAMPLES}")
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
message("\n")
get_directory_property(cpp_definitions COMPILE_DEFINITIONS)
message("Compile definitions: ............... ${cpp_definitions}")
message("CC: ................................ ${CMAKE_C_COMPILER}")
message("CFLAGS: ............................ ${CMAKE_C_FLAGS}")
message("\n")
