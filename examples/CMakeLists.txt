function(add_example name)
  set(target_name ${name}_example)
  add_executable(${target_name} ${name}.c)
  target_include_directories(${target_name} PRIVATE
    ${PROJECT_SOURCE_DIR}/include
  )
  target_link_libraries(${target_name}
    secp256k1
    $<$<PLATFORM_ID:Windows>:bcrypt>
  )
  if(NOT BUILD_SHARED_LIBS AND MSVC)
    # We pass /IGNORE:4217 to the MSVC linker to suppress warning 4217 when
    # importing variables from a statically linked secp256k1.
    # (See the Libtool manual, section "Windows DLLs" for background.)
    target_link_options(${target_name} INTERFACE /IGNORE:4217)
  endif()

  set(test_name ${name}_example)
  add_test(NAME ${test_name} COMMAND ${target_name})
endfunction()

add_example(ecdsa)

if(SECP256K1_ENABLE_MODULE_ECDH)
  add_example(ecdh)
endif()

if(SECP256K1_ENABLE_MODULE_SCHNORRSIG)
  add_example(schnorr)
endif()
