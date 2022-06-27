# Copyright 2022 Hennadii Stepanov
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

add_library(example INTERFACE)
target_include_directories(example
  INTERFACE
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(example
  INTERFACE
    secp256k1
    $<$<PLATFORM_ID:Windows>:bcrypt>
)
target_link_options(example
  INTERFACE
    $<$<NOT:$<PLATFORM_ID:Darwin>>:-static>
)

# include_directories(${PROJECT_SOURCE_DIR}/include)
# link_libraries(secp256k1)

add_executable(ecdsa_example ecdsa.c)
target_link_libraries(ecdsa_example PRIVATE example)

if(ENABLE_MODULE_ECDH)
  add_executable(ecdh_example ecdh.c)
  target_link_libraries(ecdh_example PRIVATE example)
endif()

if(ENABLE_MODULE_SCHNORRSIG)
  add_executable(schnorr_example schnorr.c)
  target_link_libraries(schnorr_example PRIVATE example)
endif()
