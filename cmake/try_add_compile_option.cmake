include(CheckCCompilerFlag)

function(try_add_compile_option option)
  set(result "HAS_C_${option}_OPTION")
  check_c_compiler_flag(${option} ${result})
  if(${result})
    get_property(compile_options
      DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      PROPERTY COMPILE_OPTIONS
    )
    list(APPEND compile_options "${option}")
    set_property(
      DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      PROPERTY COMPILE_OPTIONS "${compile_options}"
    )
  endif()
endfunction()
