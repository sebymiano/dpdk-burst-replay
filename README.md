# DPDK burst replay tool

## Introduction

This is a modified version of the `dpdk-replay` tool, which was originally published on this [GitHub repository](https://github.com/FraudBuster/dpdk-burst-replay).
The tool is designed to provide high DPDK performances (up to 148Mpps with 64B packets) to burst any pcap dump on a single NIC port(s).

To do so, the pcap files will be cached on hugepages before being sent through DPDK.

## How to play with it

### Install dependencies

* dpdk v23.11.2 (LTS) or later
* libnuma-dev
* libyaml-dev
* libcyaml-dev
* libcsv-dev
* That's all.

```bash
$ sudo apt install libnuma-dev libyaml-dev libcyaml-dev libcsv-dev -y
```

NB: libpcap is not required, as dpdk-replay process pcap files manually.

## Compiling and installing it (new way)
This is the recommended way to compile and install `dpdk-replay`.

Since the new `dpdk-replay` version relies on the libcyaml library, you need to make sure the repo is cloned with the `--recurse-submodules` option.
If you haven't done it, you can still do it with the following command:
```bash
$ git submodule update --init --recursive
```

Then, you can compile and install `dpdk-replay` with the following commands:

```bash
$ mkdir build; cd build
$ cmake ..
$ make
$ sudo make install
```

### Launching it (new way)
It is now possible to use a configuration file to configure the `dpdk-replay` tool.

The configuration file is a YAML file that contains the following syntax:

```yaml
---
# Here you can specify the pcap file to replay
# and the number of tx queues
# Every trace will use a separate TX core to send packets
# If you want to push a specific trace to the limits (e.g., 148Mpps),
# you can specify the same trace N times, so that N cores will be used to
# send packets from the same trace.
# Of course, this will not ensure that the packets will be sent in the same order.
traces: 
  - path: "/users/smiano/maestro-eval/pcaps/uniform_64B.pcap"
    tx_queues: 8
# Specify here the numa node to use
numacore: 0
# Specify the number of runs to loop the pcap file
nbruns: 100000000
# If you specify the timeout, the PCAP will be replayed until the timeout is reached
timeout: 10
# Specify the maximum packets per second
max_mpps: -1
# Specify the maximum megabits per second
max_mbps: -1
# Set this to true if you want to write the results in a CSV file
write_csv: True
# Set this to true if you want to wait and press enter before starting the replay
wait_enter: False
# Set this to true if you want to enable slow mode
slow_mode: False
# Set this to true if you want to convert the results to JSON format (only if write_csv is True)
convert_to_json: True
# Specify the number of RX queues and cores
nb_rx_queues: 16
nb_rx_cores: 4
# Specify the PCI address of the NIC to use to send packets
send_port_pci: 0000:51:00.0
# Specify the PCI address of the NIC to use to read results from
# By default, the 1st PCI address of the send_port_pci should be in this list
# If you want to read results from multiple NICs, you can specify them here
stats:
  - pci_id: 0000:51:00.0
    file_name: "result_v1.csv"
  - pci_id: 0000:51:00.1
    file_name: "result_v2.csv"
# Specify the log level
loglevel: TRACE

```

Then, you can launch `dpdk-replay` with the following command:

```bash
$ dpdk-replay --config config.yaml
```

## BSD LICENCE

Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.

Copyright 2023 Sebastiano Miano. All rights reserved.
