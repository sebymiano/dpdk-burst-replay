# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.

# Add the executable target
add_executable(dpdk-replay
    main.c
    cpus.c
    dpdk.c
    pcap.c
    utils.c
)

# Add CFLAGS for dpdk-replay
target_compile_options(dpdk-replay PRIVATE -Wno-expansion-to-defined)

# Use pkg-config to find and set DPDK_CFLAGS and DPDK_LDFLAGS_STATIC
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

# Add DPDK_CFLAGS and DPDK_LDFLAGS_STATIC to the target
target_compile_options(dpdk-replay PRIVATE ${DPDK_CFLAGS})
target_link_libraries(dpdk-replay PRIVATE ${DPDK_STATIC_LDFLAGS})

# If you need to link with 'libcsv', uncomment the following lines and make sure to find the package.
target_link_libraries(dpdk-replay PRIVATE csv)