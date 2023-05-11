function(check_arm32_assembly)
  # This avoids running a linker.
  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

  try_compile(HAVE_ARM32_ASM
    ${CMAKE_BINARY_DIR}/check_arm32_assembly
    SOURCES ${CMAKE_SOURCE_DIR}/cmake/source_arm32.s
  )
endfunction()
