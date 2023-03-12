include(CheckCCompilerFlag)

# Append flags to the COMPILE_OPTIONS directory property if CC accepts them.
macro(try_add_compile_option)
  check_cflags_internal("${ARGV}" result)
  if(result)
    add_compile_options(${ARGV})
  endif()
endmacro()

function(check_cflags_internal flags output)
  string(MAKE_C_IDENTIFIER "${flags}" result)
  string(TOUPPER "${result}" result)
  set(result "C_SUPPORTS_${result}")
  if(NOT MSVC)
    set(CMAKE_REQUIRED_FLAGS "-Werror")
  endif()

  # This avoids running a linker.
  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
  check_c_compiler_flag("${flags}" ${result})

  set(${output} ${${result}} PARENT_SCOPE)
endfunction()
