#SPDX - License - Identifier : BSD - 3 - Clause
#Copyright 2023 Sebastiano Miano.All rights reserved.

#Add the executable target
add_executable(dpdk -
               replay main.c cpus.c dpdk.c pcap.c utils.c argparse.c log.c)

#Add CFLAGS for dpdk - replay
    target_compile_options(dpdk - replay PRIVATE - Wno - expansion - to -
                           defined - DLOG_USE_COLOR)

#Use pkg - config to find and set DPDK_CFLAGS and DPDK_LDFLAGS_STATIC
        find_package(PkgConfig REQUIRED)
            pkg_check_modules(DPDK REQUIRED libdpdk)

#Add DPDK_CFLAGS and DPDK_LDFLAGS_STATIC to the target
                target_compile_options(dpdk - replay PRIVATE ${DPDK_CFLAGS})
                    target_link_libraries(dpdk -
                                          replay PRIVATE ${DPDK_STATIC_LDFLAGS})

#Set the CMAKE_PREFIX_PATH to include the build directory
                        set(CMAKE_PREFIX_PATH
                            "${CMAKE_CURRENT_BINARY_DIR}/../libs/"
                            "libcyaml;${CMAKE_PREFIX_PATH}")
                            message(STATUS
                                    "CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")

                                pkg_check_modules(CYAML REQUIRED libcyaml)

                                    set(CYAML_STATIC_LDFLAGS
                                        "-L${CMAKE_CURRENT_BINARY_DIR}/../libs/"
                                        "libcyaml/lib;-l:libcyaml.a;-lyaml")
                                        message(STATUS
                                                "CYAML_STATIC_LDFLAGS: "
                                                "${CYAML_STATIC_LDFLAGS}")
                                            target_compile_options(
                                                dpdk -
                                                replay PRIVATE ${CYAML_CFLAGS})
                                                target_link_libraries(
                                                    dpdk -
                                                    replay PRIVATE ${
                                                        CYAML_STATIC_LDFLAGS})

#If you need to link with 'libcsv', \
    uncomment the following lines and make sure to find the package.
                                                    target_link_libraries(
                                                        dpdk -
                                                        replay PRIVATE csv)