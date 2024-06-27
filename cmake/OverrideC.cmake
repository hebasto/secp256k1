# Prefer -O2 optimization level. (-O3 is CMake's default for Release for many compilers.)
string(REGEX REPLACE "(^| )-O3( |$)" "\\1-O2\\2" CMAKE_C_FLAGS_RELEASE_INIT "${CMAKE_C_FLAGS_RELEASE_INIT}")
