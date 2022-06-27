cmake_minimum_required(VERSION 3.1)

if(CMAKE_VERSION VERSION_GREATER 3.14)
  # MSVC runtime library flags are selected by the CMAKE_MSVC_RUNTIME_LIBRARY abstraction.
  cmake_policy(SET CMP0091 NEW)
  # MSVC warning flags are not in CMAKE_<LANG>_FLAGS by default.
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
set(${PROJECT_NAME}_LIB_VERSION_CURRENT 0)
set(${PROJECT_NAME}_LIB_VERSION_REVISION 0)
set(${PROJECT_NAME}_LIB_VERSION_AGE 0)

enable_language(C)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# We do not use CMake's BUILD_SHARED_LIBS option.
option(SECP256K1_BUILD_SHARED "Build shared library." ON)
option(SECP256K1_BUILD_STATIC "Build static library." ON)
if(NOT SECP256K1_BUILD_SHARED AND NOT SECP256K1_BUILD_STATIC)
  message(FATAL_ERROR "At least one of SECP256K1_BUILD_SHARED and SECP256K1_BUILD_STATIC must be enabled.")
endif()

option(SECP256K1_ENABLE_MODULE_ECDH "Enable ECDH module." OFF)
if(SECP256K1_ENABLE_MODULE_ECDH)
  add_definitions(-DENABLE_MODULE_ECDH)
endif()

option(SECP256K1_ENABLE_MODULE_RECOVERY "Enable ECDSA pubkey recovery module." OFF)
if(SECP256K1_ENABLE_MODULE_RECOVERY)
  add_definitions(-DENABLE_MODULE_RECOVERY)
endif()

option(SECP256K1_ENABLE_MODULE_EXTRAKEYS "Enable extrakeys module." OFF)
option(SECP256K1_ENABLE_MODULE_SCHNORRSIG "Enable schnorrsig module." OFF)
if(SECP256K1_ENABLE_MODULE_SCHNORRSIG)
  set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON)
  add_definitions(-DENABLE_MODULE_SCHNORRSIG)
endif()
if(SECP256K1_ENABLE_MODULE_EXTRAKEYS)
  add_definitions(-DENABLE_MODULE_EXTRAKEYS)
endif()

option(SECP256K1_ENABLE_EXPERIMENTAL "Enable experimental configure options." OFF)
option(SECP256K1_USE_EXTERNAL_DEFAULT_CALLBACKS "Enable external default callback functions." OFF)
if(SECP256K1_USE_EXTERNAL_DEFAULT_CALLBACKS)
  add_definitions(-DUSE_EXTERNAL_DEFAULT_CALLBACKS)
endif()

set(SECP256K1_ECMULT_WINDOW_SIZE auto CACHE STRING "Window size for ecmult precomputation for verification, specified as integer in range [2..24]. \"auto\" is a reasonable setting for desktop machines (currently 15). [default=auto]")
if(SECP256K1_ECMULT_WINDOW_SIZE STREQUAL "auto")
  set(SECP256K1_ECMULT_WINDOW_SIZE 15)
endif()
if(NOT SECP256K1_ECMULT_WINDOW_SIZE MATCHES ^[1-9][0-9]*$ OR SECP256K1_ECMULT_WINDOW_SIZE LESS 2 OR SECP256K1_ECMULT_WINDOW_SIZE GREATER 24)
  message(FATAL_ERROR "SECP256K1_ECMULT_WINDOW_SIZE value is \"${SECP256K1_ECMULT_WINDOW_SIZE}\", but must an integer in range [2..24] or \"auto\".")
endif()
add_definitions(-DECMULT_WINDOW_SIZE=${SECP256K1_ECMULT_WINDOW_SIZE})

set(SECP256K1_ECMULT_GEN_PREC_BITS auto CACHE STRING "Precision bits to tune the precomputed table size for signing, specified as integer 2, 4 or 8. \"auto\" is a reasonable setting for desktop machines (currently 4). [default=auto]")
set_property(CACHE SECP256K1_ECMULT_GEN_PREC_BITS PROPERTY STRINGS auto 2 4 8)
if(SECP256K1_ECMULT_GEN_PREC_BITS STREQUAL "auto")
  set(SECP256K1_ECMULT_GEN_PREC_BITS 4)
endif()
if(NOT SECP256K1_ECMULT_GEN_PREC_BITS STREQUAL 2 AND NOT SECP256K1_ECMULT_GEN_PREC_BITS STREQUAL 4 AND NOT SECP256K1_ECMULT_GEN_PREC_BITS STREQUAL 8)
  message(FATAL_ERROR "SECP256K1_ECMULT_GEN_PREC_BITS value is \"${SECP256K1_ECMULT_GEN_PREC_BITS}\", but must an integer 2, 4, 8, or \"auto\".")
endif()
add_definitions(-DECMULT_GEN_PREC_BITS=${SECP256K1_ECMULT_GEN_PREC_BITS})

option(SECP256K1_USE_FORCE_WIDEMUL_INT128 "Force the use of the (unsigned) __int128 based wide multiplication implementation." OFF)
if(SECP256K1_USE_FORCE_WIDEMUL_INT128)
  add_definitions(-DUSE_FORCE_WIDEMUL_INT128)
endif()
option(SECP256K1_USE_FORCE_WIDEMUL_INT64 "Force the use of the (u)int64_t based wide multiplication implementation." OFF)
if(SECP256K1_USE_FORCE_WIDEMUL_INT64)
  add_definitions(-DUSE_FORCE_WIDEMUL_INT64)
endif()
if(SECP256K1_USE_FORCE_WIDEMUL_INT128 AND SECP256K1_USE_FORCE_WIDEMUL_INT64)
  message(FATAL_ERROR "SECP256K1_USE_FORCE_WIDEMUL_INT128 and SECP256K1_USE_FORCE_WIDEMUL_INT64 cannot be enabled simultaneously.")
endif()
mark_as_advanced(FORCE
  SECP256K1_USE_FORCE_WIDEMUL_INT128
  SECP256K1_USE_FORCE_WIDEMUL_INT64
)

option(SECP256K1_BUILD_BENCHMARK "Build benchmarks." ON)
option(SECP256K1_BUILD_TESTS "Build tests." ON)
option(SECP256K1_BUILD_EXHAUSTIVE_TESTS "Build exhaustive tests." ON)
option(SECP256K1_BUILD_EXAMPLES "Build examples." OFF)

# Redefine configuration flags.
set(CMAKE_C_FLAGS_DEBUG "-O0 -g3")
if(MSVC)
  set(CMAKE_C_FLAGS_RELEASE "/O2 /Ob2")
else()
  set(CMAKE_C_FLAGS_RELEASE "-O2 -g")
endif()

# Define custom "Coverage" build type.
set(CMAKE_C_FLAGS_COVERAGE "-DCOVERAGE -O0 --coverage -Wno-unused-parameter" CACHE STRING
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
  CMAKE_C_FLAGS_COVERAGE
  CMAKE_EXE_LINKER_FLAGS_COVERAGE
  CMAKE_SHARED_LINKER_FLAGS_COVERAGE
)
get_property(cached_cmake_build_type CACHE CMAKE_BUILD_TYPE PROPERTY TYPE)
if(cached_cmake_build_type)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
    STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo" "Coverage"
  )
endif()
set(default_build_type "Release")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to \"${default_build_type}\" as none was specified")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()

include(cmake/TryAddCompileOption.cmake)
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
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
set(CMAKE_VISIBILITY_INLINES_HIDDEN TRUE)

include(CTest)
if(SECP256K1_BUILD_BENCHMARK OR SECP256K1_BUILD_TESTS OR SECP256K1_BUILD_EXHAUSTIVE_TESTS OR SECP256K1_BUILD_EXAMPLES)
  # We do not use CMake CTest's BUILD_TESTING option.
  enable_testing()
endif()

add_subdirectory(src)
if(SECP256K1_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

message("\n")
message("secp256k1 configure summary")
message("===========================")
message("Build artifacts:")
message("  shared library ...................... ${SECP256K1_BUILD_SHARED}")
message("  static library ...................... ${SECP256K1_BUILD_STATIC}")
message("Optional modules:")
message("  ECDH ................................ ${SECP256K1_ENABLE_MODULE_ECDH}")
message("  ECDSA pubkey recovery ............... ${SECP256K1_ENABLE_MODULE_RECOVERY}")
message("  extrakeys ........................... ${SECP256K1_ENABLE_MODULE_EXTRAKEYS}")
message("  schnorrsig .......................... ${SECP256K1_ENABLE_MODULE_SCHNORRSIG}")
message("Parameters:")
message("  ecmult window size .................. ${SECP256K1_ECMULT_WINDOW_SIZE}")
message("  ecmult gen precision bits ........... ${SECP256K1_ECMULT_GEN_PREC_BITS}")
message("Optional features:")
message("  external callbacks .................. ${SECP256K1_USE_EXTERNAL_DEFAULT_CALLBACKS}")
if(SECP256K1_USE_FORCE_WIDEMUL_INT128)
  set(widemul_status "int128")
elseif(SECP256K1_USE_FORCE_WIDEMUL_INT64)
  set(widemul_status "int64")
else()
  set(widemul_status OFF)
endif()
message("  override wide multiplication ........ ${widemul_status}")
message("Optional binaries:")
message("  benchmark ........................... ${SECP256K1_BUILD_BENCHMARK}")
message("  tests ............................... ${SECP256K1_BUILD_TESTS}")
message("  exhaustive tests .................... ${SECP256K1_BUILD_EXHAUSTIVE_TESTS}")
message("  examples ............................ ${SECP256K1_BUILD_EXAMPLES}")
message("")
if(CMAKE_CROSSCOMPILING)
  set(cross_status "TRUE, for ${CMAKE_SYSTEM_NAME}, ${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(cross_status "FALSE")
endif()
message("Cross compiling ....................... ${cross_status}")
get_directory_property(definitions COMPILE_DEFINITIONS)
string(REPLACE ";" " " definitions "${definitions}")
message("Preprocessor defined macros ........... ${definitions}")
message("C compiler ............................ ${CMAKE_C_COMPILER}")
message("CFLAGS ................................ ${CMAKE_C_FLAGS}")
get_directory_property(compile_options COMPILE_OPTIONS)
string(REPLACE ";" " " compile_options "${compile_options}")
message("Compile options ....................... " ${compile_options})
if(DEFINED CMAKE_BUILD_TYPE)
  message("Build type:")
  message(" - CMAKE_BUILD_TYPE ................... ${CMAKE_BUILD_TYPE}")
  string(TOUPPER "${CMAKE_BUILD_TYPE}" build_type)
  message(" - CFLAGS ............................. ${CMAKE_C_FLAGS_${build_type}}")
  message(" - LDFLAGS for executables ............ ${CMAKE_EXE_LINKER_FLAGS_${build_type}}")
  message(" - LDFLAGS for shared libraries ....... ${CMAKE_SHARED_LINKER_FLAGS_${build_type}}")
else()
  message("Available configurations .............. ${CMAKE_CONFIGURATION_TYPES}")
  message("Debug configuration:")
  message(" - CFLAGS ............................. ${CMAKE_C_FLAGS_DEBUG}")
  message(" - LDFLAGS for executables ............ ${CMAKE_EXE_LINKER_FLAGS_DEBUG}")
  message(" - LDFLAGS for shared libraries ....... ${CMAKE_SHARED_LINKER_FLAGS_DEBUG}")
  message("Release configuration:")
  message(" - CFLAGS ............................. ${CMAKE_C_FLAGS_RELEASE}")
  message(" - LDFLAGS for executables ............ ${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
  message(" - LDFLAGS for shared libraries ....... ${CMAKE_SHARED_LINKER_FLAGS_RELEASE}")
endif()
message("\n")
