# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023 Sebastiano Miano. All rights reserved.

cmake_minimum_required(VERSION 3.12)
project(dpdk-burst-replay VERSION 1.1.1)

# Set the installation prefix to /usr
set(CMAKE_INSTALL_PREFIX /usr)

# Define the current version using Git commit hash
execute_process(
    COMMAND git rev-parse HEAD
    OUTPUT_VARIABLE DPDK_REPLAY_VERSION_GIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_definitions(-DDPDK_REPLAY_VERSION_GIT="${DPDK_REPLAY_VERSION_GIT}")

# Find libyaml on the system
find_library(LIBYAML_LIBRARY NAMES yaml)

# If libyaml is found, build libcyaml
if (LIBYAML_LIBRARY)
    # Execute the Makefile-based build for libcyaml
    execute_process(
        COMMAND make install VARIANT=release PREFIX=${CMAKE_CURRENT_BINARY_DIR}/libs/libcyaml
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libs/libcyaml
    )

    # Add libcyaml as a subdirectory
    # add_subdirectory(libs/libcyaml)
else()
    # Display an error message if libyaml is not found
    message(FATAL_ERROR "libyaml not found. Please install libyaml and try again.")
endif()

find_library(LIBCSV_LIBRARY NAMES csv)

if (LIBCSV_LIBRARY)
    message(STATUS "libcsv found: ${LIBCSV_LIBRARY}")
else()
    # Display an error message if libcsv is not found
    message(FATAL_ERROR "libcsv not found. Please install libcsv and try again.")
endif()

# Add the 'src' directory
add_subdirectory(src)

# Set the default build type to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags for Debug configuration
set(CMAKE_C_FLAGS_DEBUG "-ggdb -W -Wall -DDEBUG -O0")

# Compiler flags for Release configuration
set(CMAKE_C_FLAGS_RELEASE "-W -Wall -DNDEBUG -O2")

# Add additional flags based on the build type (Release/Debug)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE}}")

# Install the 'dpdk-replay' binary to /usr/bin
install(TARGETS dpdk-replay
    RUNTIME DESTINATION bin
)