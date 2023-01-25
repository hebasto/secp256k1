function(check_string_option_value option)
  get_property(expected_values CACHE ${option} PROPERTY STRINGS)
  if(NOT expected_values)
    message(AUTHOR_WARNING "The STRINGS property must be set before invoking `check_string_option_value' function.")
    return()
  endif()

  foreach(value IN LISTS expected_values)
    if(value STREQUAL "${${option}}")
      return()
    endif()
  endforeach()

  message(FATAL_ERROR "${option} value is \"${${option}}\", but must be one of ${expected_values}.")

endfunction()
