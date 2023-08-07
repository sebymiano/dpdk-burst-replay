# DPDK burst replay tool

## Introduction

The tool is designed to provide high DPDK performances to burst any pcap dump on
a single or multiple NIC port(s).

To do so, the pcap files will be cached on hugepages before being sent through DPDK.

## How to play with it

### Install dependencies

* dpdk v22.11.2 (LTS)
* libnuma-dev
* libyaml-dev
* That's all.

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
traces: 
  - path: "/mydata/equinix-nyc.dirA.20190117-125910.UTC.anon.64.1000000.pcap"
    tx_queues: 4
numacore: 1
nbruns: 100000000
timeout: 60
max_bitrate: 10000000000
write_csv: True
wait_enter: False
slow_mode: False
stats:
  - pci_id: 0000:81:00.0
    file_name: "result_v1_core1.csv"
send_port_pci: 0000:81:00.0
```

Then, you can launch `dpdk-replay` with the following command:

```bash
$ dpdk-replay --config config.yaml
```

## Compiling and installing it (old way)

> autoreconf -i && ./configure [--enable-debug] && make && sudo make install

OR:

> RTE_SDK=<RTE_SDK_PATH> make -f DPDK_Makefile && sudo cp build/dpdk-replay /usr/bin

### Launching it (old way)

> dpdk-replay [--nbruns NB] [--numacore 0|1] FILE NIC_ADDR[,NIC_ADDR...]

Example:
> dpdk-replay --nbruns 1000 --numacore 0 foobar.pcap 04:00.0,04:00.1,04:00.2,04:00.3

## TODO

* Add a configuration file or cmdline options for all code defines.
* Add an option to configure maximum bitrate.
* Add an option to send the pcap with the good pcap timers.
* Add an option to send the pcap with a multiplicative speed (like, ten times the normal speed).
* Add an option to select multiple pcap files at once.
* Be able to send dumps simultaneously on both numacores.
* Split big pkts into multiple mbufs.
* Add a Python module to facilitate scripting (something like what does scapy for tcpreplay sendpfast func).
* Manage systems with more than 2 numa cores.
* Use the maximum NICs capabilities (Tx queues/descriptors).

## BSD LICENCE

Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.

Copyright 2023 Sebastiano Miano. All rights reserved.
