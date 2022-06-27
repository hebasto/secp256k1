cmake_minimum_required(VERSION 3.1)
if(CMAKE_VERSION VERSION_GREATER 3.14)
  # MSVC warning flags are not in CMAKE_<LANG>_FLAGS by default.
  # See: https://cmake.org/cmake/help/latest/policy/CMP0092.html
  cmake_policy(SET CMP0092 NEW)
endif()

# The package (a.k.a. release) version is based on semantic versioning 2.0.0 of
# the API. All changes in experimental modules are treated as
# backwards-compatible and therefore at most increase the minor version.
project(secp256k1 VERSION 0.1.0 LANGUAGES)

# The library version is based on libtool versioning of the ABI. The set of
# rules for updating the version can be found here:
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
# All changes in experimental modules are treated as if they don't affect the
# interface and therefore only increase the revision.
set(secp256k1_LIB_VERSION_CURRENT 0)
set(secp256k1_LIB_VERSION_REVISION 0)
set(secp256k1_LIB_VERSION_AGE 0)

enable_language(C)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_EXTENSIONS OFF)

# We do not use CMake's BUILD_SHARED_LIBS option.
option(SECP_BUILD_SHARED "Build shared library." ON)
option(SECP_BUILD_STATIC "Build static library." ON)
if(NOT SECP_BUILD_SHARED AND NOT SECP_BUILD_STATIC)
  message(FATAL_ERROR "At least one of SECP_BUILD_SHARED and SECP_BUILD_STATIC must be enabled.")
endif()

option(SECP_ENABLE_MODULE_ECDH "Enable ECDH module." OFF)
if(SECP_ENABLE_MODULE_ECDH)
  add_definitions(-DENABLE_MODULE_ECDH)
endif()

option(SECP_ENABLE_MODULE_RECOVERY "Enable ECDSA pubkey recovery module." OFF)
if(SECP_ENABLE_MODULE_RECOVERY)
  add_definitions(-DENABLE_MODULE_RECOVERY)
endif()

option(SECP_ENABLE_MODULE_EXTRAKEYS "Enable extrakeys module." OFF)
option(SECP_ENABLE_MODULE_SCHNORRSIG "Enable schnorrsig module." OFF)
if(SECP_ENABLE_MODULE_SCHNORRSIG)
  set(SECP_ENABLE_MODULE_EXTRAKEYS ON)
  add_definitions(-DENABLE_MODULE_SCHNORRSIG)
endif()
if(SECP_ENABLE_MODULE_EXTRAKEYS)
  add_definitions(-DENABLE_MODULE_EXTRAKEYS)
endif()

option(SECP_ENABLE_EXPERIMENTAL "Enable experimental configure options." OFF)
option(SECP_USE_EXTERNAL_DEFAULT_CALLBACKS "Enable external default callback functions." OFF)
if(SECP_USE_EXTERNAL_DEFAULT_CALLBACKS)
  add_definitions(-DUSE_EXTERNAL_DEFAULT_CALLBACKS)
endif()

set(SECP_ECMULT_WINDOW_SIZE auto CACHE STRING "Window size for ecmult precomputation for verification, specified as integer in range [2..24]. \"auto\" is a reasonable setting for desktop machines (currently 15). [default=auto]")
if(SECP_ECMULT_WINDOW_SIZE STREQUAL "auto")
  set(SECP_ECMULT_WINDOW_SIZE 15)
endif()
if(NOT SECP_ECMULT_WINDOW_SIZE MATCHES ^[1-9][0-9]*$ OR SECP_ECMULT_WINDOW_SIZE LESS 2 OR SECP_ECMULT_WINDOW_SIZE GREATER 24)
  message(FATAL_ERROR "SECP_ECMULT_WINDOW_SIZE value is \"${SECP_ECMULT_WINDOW_SIZE}\", but must an integer in range [2..24] or \"auto\".")
endif()
add_definitions(-DECMULT_WINDOW_SIZE=${SECP_ECMULT_WINDOW_SIZE})

set(SECP_ECMULT_GEN_PREC_BITS auto CACHE STRING "Precision bits to tune the precomputed table size for signing, specified as integer 2, 4 or 8. \"auto\" is a reasonable setting for desktop machines (currently 4). [default=auto]")
set_property(CACHE SECP_ECMULT_GEN_PREC_BITS PROPERTY STRINGS auto 2 4 8)
if(SECP_ECMULT_GEN_PREC_BITS STREQUAL "auto")
  set(SECP_ECMULT_GEN_PREC_BITS 4)
endif()
if(NOT SECP_ECMULT_GEN_PREC_BITS STREQUAL 2 AND NOT SECP_ECMULT_GEN_PREC_BITS STREQUAL 4 AND NOT SECP_ECMULT_GEN_PREC_BITS STREQUAL 8)
  message(FATAL_ERROR "SECP_ECMULT_GEN_PREC_BITS value is \"${SECP_ECMULT_GEN_PREC_BITS}\", but must an integer 2, 4, 8, or \"auto\".")
endif()
add_definitions(-DECMULT_GEN_PREC_BITS=${SECP_ECMULT_GEN_PREC_BITS})

option(SECP_USE_FORCE_WIDEMUL_INT128 "Force the use of the (unsigned) __int128 based wide multiplication implementation." OFF)
if(SECP_USE_FORCE_WIDEMUL_INT128)
  add_definitions(-DUSE_FORCE_WIDEMUL_INT128)
endif()
option(SECP_USE_FORCE_WIDEMUL_INT64 "Force the use of the (u)int64_t based wide multiplication implementation." OFF)
if(SECP_USE_FORCE_WIDEMUL_INT64)
  add_definitions(-DUSE_FORCE_WIDEMUL_INT64)
endif()
if(SECP_USE_FORCE_WIDEMUL_INT128 AND SECP_USE_FORCE_WIDEMUL_INT64)
  message(FATAL_ERROR "SECP_USE_FORCE_WIDEMUL_INT128 and SECP_USE_FORCE_WIDEMUL_INT64 cannot be enabled simultaneously.")
endif()

option(SECP_BUILD_BENCHMARK "Build benchmarks." ON)
option(SECP_BUILD_TESTS "Build tests." ON)
option(SECP_BUILD_EXHAUSTIVE_TESTS "Build exhaustive tests." ON)
option(SECP_BUILD_EXAMPLES "Build examples." OFF)

mark_as_advanced(FORCE
  SECP_USE_FORCE_WIDEMUL_INT128
  SECP_USE_FORCE_WIDEMUL_INT64
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

include(CTest)
if(SECP_BUILD_BENCHMARK OR SECP_BUILD_TESTS OR SECP_BUILD_EXHAUSTIVE_TESTS OR SECP_BUILD_EXAMPLES)
  # We do not use CMake CTest's BUILD_TESTING option.
  enable_testing()
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND NOT MSVC)
  # set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

add_subdirectory(src)
if(SECP_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

message("\n")
message("Configure summary")
message("=================")
message("secp256k1 library:")
message("  shared ........................... ${SECP_BUILD_SHARED}")
message("  static ........................... ${SECP_BUILD_STATIC}")
message("Optional modules:")
message("  ECDH ............................. ${SECP_ENABLE_MODULE_ECDH}")
message("  ECDSA pubkey recovery ............ ${SECP_ENABLE_MODULE_RECOVERY}")
message("  extrakeys ........................ ${SECP_ENABLE_MODULE_EXTRAKEYS}")
message("  schnorrsig ....................... ${SECP_ENABLE_MODULE_SCHNORRSIG}")
message("Parameters:")
message("  ecmult window size ............... ${SECP_ECMULT_WINDOW_SIZE}")
message("  ecmult gen precision bits ........ ${SECP_ECMULT_GEN_PREC_BITS}")
message("Optional features:")
message("  external callbacks ............... ${SECP_USE_EXTERNAL_DEFAULT_CALLBACKS}")
if(SECP_USE_FORCE_WIDEMUL_INT128)
  message("  override wide multiplication ..... int128")
endif()
if(SECP_USE_FORCE_WIDEMUL_INT64)
  message("  override wide multiplication ..... int64")
endif()
message("Optional binaries:")
message("  benchmark ........................ ${SECP_BUILD_BENCHMARK}")
message("  tests ............................ ${SECP_BUILD_TESTS}")
message("  exhaustive tests ................. ${SECP_BUILD_EXHAUSTIVE_TESTS}")
message("  examples ......................... ${SECP_BUILD_EXAMPLES}")
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
