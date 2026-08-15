cmake_minimum_required(VERSION 3.18)
project(darkdex LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)

# host cores (build on the redroid host; arm64 g++ produces host binaries that
# read the container process /proc/<pid>/mem from outside the Android sandbox)
add_executable(darkdex_carve    darkdex_carve.cpp)
add_executable(darkdex_recover  darkdex_recover.cpp)
add_executable(darkdex_intel    darkdex_intel.cpp)
add_executable(darkdex_artwalk  darkdex_artwalk.cpp)   # v2: ART DexFile-object walker
add_executable(darkdex_grab     darkdex_grab.cpp)      # v2: JIT-tracer event grabber
add_executable(cdex_to_dex      cdex_to_dex.cpp)       # v2: real CompactDex expansion
target_compile_definitions(cdex_to_dex PRIVATE DARKDEX_STANDALONE)

# native/darkdex_trace.bt is a bpftrace program (no compilation); host/darkdex.sh
# fills its @LIBDEX@/@LIBART@ placeholders and runs it.

# optional in-process libdarkdex.so for the on-device app (root cookie dump path)
option(DARKDEX_NDK "Build the in-process libdarkdex.so" OFF)
if(DARKDEX_NDK)
  add_library(darkdex SHARED art_cookie.cpp cdex_to_dex.cpp)
  find_library(log-lib log)
  target_link_libraries(darkdex ${log-lib})
endif()
