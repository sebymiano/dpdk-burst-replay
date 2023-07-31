# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.

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