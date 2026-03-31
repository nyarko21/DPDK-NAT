cmake_minimum_required(VERSION 3.20)
project(eloictl C)

# C standard
set(CMAKE_C_STANDARD 11)

add_compile_options(-O3 -march=native)

# Find pkg-config
find_package(PkgConfig REQUIRED)

# Use pkg-config to get DPDK flags
pkg_check_modules(DPDK REQUIRED libdpdk)

# Include DPDK headers AND local headers
include_directories(
    ${DPDK_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/include
)

# Add compiler flags from pkg-config
add_compile_options(${DPDK_CFLAGS_OTHER})

# Add source files
file(GLOB SOURCES "src/*.c")

# Build executable
add_executable(eloictl ${SOURCES})

# Link DPDK libraries
target_link_libraries(eloictl ${DPDK_LIBRARIES})