#SPDX - License - Identifier : BSD - 3 - Clause
#Copyright 2018 Jonathan Ribas, FraudBuster.All rights reserved.

bin_PROGRAMS = dpdk - replay dpdk_replay_SOURCES =
                   main.c cpus.c dpdk.c pcap.c utils.c log.c

                       CFLAGS +=
    -Wno - expansion - to - defined DPDK_CFLAGS =
        -O3 $(shell pkg - config-- cflags libdpdk)
            DPDK_LDFLAGS_STATIC = $(shell pkg - config-- static --libs libdpdk)

            dpdk_replay_CFLAGS : = $(CFLAGS) $(DPDK_CFLAGS) dpdk_replay_LDFLAGS
    : = $(LDFLAGS) $(DPDK_LDFLAGS_STATIC) - lcsv
