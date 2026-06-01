# This emulates Libtool to make sure Libtool and CMake agree on the ABI version.
# The `version_type` variable is set in autotools-aux/m4/libtool.m4.
# For the `major` and `versuffix` variables, see below "Calculate the version
# variables" in autotools-aux/ltmain.sh.
function(secp256k1_set_libtool_abi_version target current revision age)
  if(CMAKE_SYSTEM_NAME MATCHES "^(Linux|FreeBSD)$")
    # version_type = linux | freebsd-elf
    # major = $current - $age
    # versuffix = $major.$age.$revision
    math(EXPR _major "${current} - ${age}")
    set_target_properties(${target} PROPERTIES
      SOVERSION ${_major}
      VERSION ${_major}.${age}.${revision}
    )
  elseif(APPLE)
    math(EXPR _compatibility "${current} + 1")
    set_target_properties(${target} PROPERTIES
      MACHO_COMPATIBILITY_VERSION ${_compatibility}
      MACHO_CURRENT_VERSION ${_compatibility}.${revision}
    )
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # version_type = windows
    # major = $current - $age
    # versuffix = $major
    math(EXPR _major "${current} - ${age}")
    set(_windows_name "secp256k1")
    if(MSVC)
      set(_windows_name "${PROJECT_NAME}")
    endif()
    set_target_properties(${target} PROPERTIES
      ARCHIVE_OUTPUT_NAME "${_windows_name}"
      RUNTIME_OUTPUT_NAME "${_windows_name}-${_major}"
    )
  endif()
endfunction()
