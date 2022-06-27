# Copyright 2022 Hennadii Stepanov
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

include(CheckCCompilerFlag)

function(secp_try_append_cflag dashed_flag)
  string(REGEX REPLACE "^(-)" "" flag ${dashed_flag})
  check_c_compiler_flag(${dashed_flag} ${flag})
  if(${flag})
    string(STRIP "${CMAKE_C_FLAGS} ${dashed_flag}" CMAKE_C_FLAGS)
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} PARENT_SCOPE)
  endif()
endfunction()
