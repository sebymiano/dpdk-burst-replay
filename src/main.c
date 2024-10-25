/*
  SPDX-License-Identifier: BSD-3-Clause
  Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.
*/

#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>

#include <rte_ethdev.h>

#include "config_yaml.h"
#include "argparse.h"
#include "main.h"

#include "log.h"

void usage(void)
{
    puts("dpdk-replay \n" \
         "  --config <config.yaml> : path to the configuration file\n" \
         "  --help                 : show this help message and exit\n");
    return ;
}

#ifdef DEBUG
void print_opts(const struct cmd_opts* opts)
{
    if (!opts)
        return ;
    log_info("--");
    log_info("numacore: %i", (int)(opts->numacore));
    log_info("nb runs: %u", opts->nbruns);
    log_info("timeout: %u", opts->timeout);
    log_info("wait-enter: %s", opts->wait ? "yes" : "no");
    log_info("write-csv: %s", opts->write_csv ? "yes" : "no");
    log_info("slow-mode: %s", opts->slow_mode ? "yes" : "no");
    log_info("max_mpps: %.2f", opts->max_mpps);
    log_info("max_mbps: %.2f", opts->max_mbps);
    log_info("nb RX queues: %u", opts->nb_rx_queues);
    log_info("nb RX cores: %u", opts->nb_rx_cores);

    log_info("nb traces: %u", opts->nb_traces);
    for (int i = 0; i < opts->nb_traces; i++) {
        log_info("trace[%d]: %s", i, opts->traces[i].path);
        log_info("tx_queues[%d]: %d", i, opts->traces[i].tx_queues);
    }
    
    log_info("pci nic ports:");
    for (int i = 0; i < opts->nb_pcicards; i++)
        log_info(" %s", opts->pcicards[i]);

    for (int i = 0; i < opts->nb_stats; i++)
        log_info("stats[%d]: %s", i, opts->stats[i]);

    for (int i = 0; i < opts->nb_stats_file_name; i++)
        log_info("stats_name[%d]: %s", i, opts->stats_name[i]);

    log_info("Log level: %s", log_level_string(opts->loglevel));
    
    log_info("--");
    return ;
}
#endif /* DEBUG */

char** str_to_pcicards_list(struct cmd_opts* opts, char* pcis)
{
    char** list = NULL;
    int i;

    if (!pcis || !opts)
        return (NULL);

    for (i = 1; ; i++) {
        list = realloc(list, sizeof(*list) * (i + 1));
        if (!list)
            return (NULL);
        list[i - 1] = pcis;
        list[i] = NULL;
        while (*pcis != '\0' && *pcis != ',')
            pcis++;
        if (*pcis == '\0')
            break;
        else { /* , */
            *pcis = '\0';
            pcis++;
        }
    }
    opts->nb_pcicards = i;
    return (list);
}

bool str_in_list(const char *str, char **list, int len) {
    for (int i = 0; i < len; i++) {
        if (strcmp(str, list[i]) == 0) {
            return true;
        }
    }
    return false;
}

char** str_to_stats_list(struct cmd_opts* opts, char* stats)
{
    char** list = NULL;
    int i;

    if (!stats || !opts)
        return (NULL);

    for (i = 1; ; i++) {
        list = realloc(list, sizeof(*list) * (i + 1));
        if (!list)
            return (NULL);
        list[i - 1] = stats;
        list[i] = NULL;
        while (*stats != '\0' && *stats != ',')
            stats++;
        if (*stats == '\0')
            break;
        else { /* , */
            *stats = '\0';
            stats++;
        }
    }
    opts->nb_stats = i;
    return (list);
}

char** str_to_stats_name_list(struct cmd_opts* opts, char* stats)
{
    char** list = NULL;
    int i;

    if (!stats || !opts)
        return (NULL);

    for (i = 1; ; i++) {
        list = realloc(list, sizeof(*list) * (i + 1));
        if (!list)
            return (NULL);
        list[i - 1] = stats;
        list[i] = NULL;
        while (*stats != '\0' && *stats != ',')
            stats++;
        if (*stats == '\0')
            break;
        else { /* , */
            *stats = '\0';
            stats++;
        }
    }

    opts->nb_stats_file_name = i;
    return (list);
}

int parse_config_file(const char *config_file, struct cmd_opts* opts) {
    int ret = 0;
    cyaml_err_t err;
    config_t *cfg;

    /* Load input file. */
    err = cyaml_load_file(config_file, &config, &top_schema, (cyaml_data_t **)&cfg, NULL);
    if (err != CYAML_OK) {
        log_fatal("ERROR: %s", cyaml_strerror(err));
        return EXIT_FAILURE;
    }

    /* Check whether a pcap is set and the send port is set */
    if (cfg->traces_count == 0 || cfg->send_port_pci == NULL) {
        log_fatal("ERROR: You must specify at least one pcap file and the send port");
        return EXIT_FAILURE;
    }

    /* Assign traces to the opts struct */
    opts->traces = malloc(sizeof(trace_t) * cfg->traces_count);
    if (!opts->traces) {
        log_fatal("ERROR: Cannot allocate memory for traces");
        return EXIT_FAILURE;
    }
    for (int i = 0; i < cfg->traces_count; i++) {
        opts->traces[i].path = strdup(cfg->traces[i].path);
        opts->traces[i].tx_queues = cfg->traces[i].tx_queues;
    }
    opts->nb_traces = cfg->traces_count;

    /* Check whether the numa node is correct */
    if (cfg->numacore < 0 || cfg->numacore > 2) {
        log_fatal("ERROR: The NUMA node must be between 0 and 2");
        return EXIT_FAILURE;
    }
    opts->numacore = cfg->numacore;

    /* Check whether the number of runs is correct */
    if (cfg->nbruns <= 0) {
        log_fatal("ERROR: The number of runs must be greater than 0");
        return EXIT_FAILURE;
    }
    opts->nbruns = cfg->nbruns;

    /* Check whether the timeout is correct */
    if (cfg->timeout <= 0) {
        log_fatal("ERROR: The timeout must be greater than 0");
        return EXIT_FAILURE;
    }
    opts->timeout = cfg->timeout;

    if (cfg->max_mpps == -1) {
        log_warn("Bitrate (Mpps) is UNLIMITED");
    }
    /* Check whether the max bitrate is correct */
    if (cfg->max_mpps < -1) {
        log_fatal("ERROR: The max bitrate (Mpps) must be greater than 0");
        return EXIT_FAILURE;
    }
    opts->max_mpps = cfg->max_mpps;

    if (cfg->max_mbps == -1) {
        log_warn("Bitrate (Mbps) is UNLIMITED");
    }
    /* Check whether the max bitrate is correct */
    if (cfg->max_mbps < -1) {
        log_fatal("ERROR: The max bitrate (Mbps) must be greater than 0");
        return EXIT_FAILURE;
    }
    opts->max_mbps = cfg->max_mbps;

    /* Check whether they are both set */
    if (cfg->max_mbps >= 0 && cfg->max_mpps >= 0) {
        log_fatal("You CANNOT set both max_mpps and max_mbps rate control");
        return EXIT_FAILURE;
    }

    cfg->wait_enter ? (opts->wait = 1) : (opts->wait = 0);
    cfg->write_csv ? (opts->write_csv = 1) : (opts->write_csv = 0);
    cfg->slow_mode ? (opts->slow_mode = 1) : (opts->slow_mode = 0);

    /* Check whether the read ports are correct */
    if (cfg->send_port_pci != NULL) {
        /* TODO: In the future we should support more */
        unsigned int send_port_count = 1;
        opts->pcicards = malloc(sizeof(char*) * send_port_count);
        if (!opts->pcicards) {
            log_fatal("ERROR: Cannot allocate memory for read ports");
            return EXIT_FAILURE;
        }
        for (int i = 0; i < send_port_count; i++) {
            opts->pcicards[i] = strdup(cfg->send_port_pci);
        }
        opts->nb_pcicards = send_port_count;
        opts->nb_total_ports = send_port_count;
    }
    log_info("Done checking send_port_pci");

    /* Check whether the stats ports are correct */
    if (cfg->stats_count > 0) {
        opts->stats = malloc(sizeof(char*) * cfg->stats_count);
        opts->stats_name = malloc(sizeof(char*) * cfg->stats_count);
        if (!opts->stats) {
            log_fatal("ERROR: Cannot allocate memory for stats ports");
            return EXIT_FAILURE;
        }
        for (int i = 0; i < cfg->stats_count; i++) {
            log_info("Checking stats count: %d", i);
            opts->stats[i] = strdup(cfg->stats[i].pci_id);
            opts->stats_name[i] = strdup(cfg->stats[i].file_name);
        }
        opts->nb_stats = cfg->stats_count;
        opts->nb_stats_file_name = cfg->stats_count;
    }
    log_info("Done checking stats count");

    if (opts->nb_stats > 0) {
        log_info("NB stats ports: %d", opts->nb_stats);
        for (int i = 0; i < opts->nb_stats; i++) {
            log_debug("Checkig stats for %s", opts->stats[i]);
            if (!str_in_list(opts->stats[i], opts->pcicards, opts->nb_pcicards)) {
                // If the device is already in the list of pci cards used for PCAP we don't count it
                opts->nb_total_ports += 1;
            }
        }
    }

    if (opts->nb_stats_file_name > 0 && opts->nb_stats_file_name != opts->nb_stats) {
        log_error("You should provide the same number of file name and stats ports");
        return (EPROTO);
    }

    opts->nb_rx_cores = cfg->nb_rx_cores;
    opts->nb_rx_queues = cfg->nb_rx_queues;

    opts->loglevel = cfg->loglevel;
    log_set_level(cfg->loglevel);

    cyaml_free(&config, &top_schema, cfg, 0);

    return EXIT_SUCCESS;
}


int parse_options(const int ac, char** av, struct cmd_opts* opts)
{
    int i;

    if (!av || !opts)
        return (EINVAL);

    if (ac != 3) {
        return (ENOENT);
    }

    if (!strcmp(av[1], "--config")) {
        log_info("Parsing configuration file %s", av[2]);
        opts->config_file = av[2];
        if (parse_config_file(opts->config_file, opts) != 0) {
            return (EPROTO);
        }
        return (0);
    } else {
        return (EINVAL);
    }
}

int check_needed_memory(const struct cmd_opts* opts, const struct pcap_ctx* pcap,
                        struct dpdk_ctx* dpdk)
{
    float           needed_mem;
    char*           hsize;

    if (!opts || !pcap || !dpdk)
        return (EINVAL);

    /* # CALCULATE THE NEEDED SIZE FOR MBUF STRUCTS */
    dpdk->mbuf_sz = sizeof(struct rte_mbuf) + pcap->max_pkt_sz;
    dpdk->mbuf_sz += (dpdk->mbuf_sz % (sizeof(int)));

    log_debug("Needed paket allocation size = "
         "(size of MBUF) + (size of biggest pcap packet), "
         "rounded up to the next multiple of an integer.");
    log_debug("(%lu + %u) + ((%lu + %u) %% %lu) = %lu",
           sizeof(struct rte_mbuf), pcap->max_pkt_sz,
           sizeof(struct rte_mbuf), pcap->max_pkt_sz,
           sizeof(int), dpdk->mbuf_sz);

    log_debug("-> Needed MBUF size: %lu", dpdk->mbuf_sz);

    /* # CALCULATE THE NEEDED NUMBER OF MBUFS */
#ifdef DPDK_RECOMMANDATIONS
    /* For number of pkts to be allocated on the mempool, DPDK says: */
    /* The optimum size (in terms of memory usage) for a mempool is when n is a
       power of two minus one: n = (2^q - 1).  */

    log_debug("Needed number of MBUFS: next power of two minus one of "
         "(nb pkts * nb ports)");

    dpdk->nb_mbuf = get_next_power_of_2(pcap->nb_pkts * opts->nb_pcicards) - 1;
#else /* !DPDK_RECOMMANDATIONS */
    /*
      Some tests shown that the perf are not so much impacted when allocating the
      exact number of wanted mbufs. I keep it simple for now to reduce the needed
      memory on large pcap.
    */
    dpdk->nb_mbuf = pcap->nb_pkts * opts->nb_pcicards;
#endif /* DPDK_RECOMMANDATIONS */
    /*
      If we have a pcap with very few packets, we need to allocate more mbufs
      than necessary to avoid rte_mempool_create failure.
    */
    if (dpdk->nb_mbuf < (MBUF_CACHE_SZ * 2))
        dpdk->nb_mbuf = MBUF_CACHE_SZ * 4;
    log_debug("-> Needed number of MBUFS: %lu", dpdk->nb_mbuf);

    /* # CALCULATE THE TOTAL NEEDED MEMORY SIZE  */
    needed_mem = dpdk->mbuf_sz * dpdk->nb_mbuf;
#ifdef DEBUG
    log_debug("Needed memory = (needed mbuf size) * (number of needed mbuf).");
    log_debug("%lu * %lu = %.0f bytes", dpdk->mbuf_sz, dpdk->nb_mbuf, needed_mem);
#endif /* DEBUG */
    hsize = nb_oct_to_human_str(needed_mem);
    if (!hsize)
        return (-1);
    log_debug("-> Needed Memory = %s", hsize);
    free(hsize);

    /* # CALCULATE THE NEEDED NUMBER OF GIGABYTE HUGEPAGES */
    if (fmod(needed_mem,((double)(1024*1024*1024))))
        dpdk->pool_sz = needed_mem / (float)(1024*1024*1024) + 1;
    else
        dpdk->pool_sz = needed_mem / (1024*1024*1024);
    log_debug("-> Needed Hugepages of 1 Go = %lu", dpdk->pool_sz);
    return (0);
}

int main(const int ac, char** av)
{
    struct cmd_opts         opts;
    struct cpus_bindings    cpus;
    struct dpdk_ctx         *dpdk_cfgs;
    struct pcap_ctx         *pcap_cfgs;
    int                     ret;
    struct thread_ctx*      stats_ctx = NULL;

    /* set default opts */
    bzero(&cpus, sizeof(cpus));
    bzero(&opts, sizeof(opts));
    // bzero(&dpdk, sizeof(dpdk));
    // bzero(&pcaps, sizeof(pcaps));
    opts.nbruns = 1;

    /* parse cmdline options */
    ret = parse_options(ac, av, &opts);
    if (ret) {
        usage();
        return (1);
    }
    
    print_opts(&opts);

    /*
      pre parse the pcap file to get needed informations:
      . number of packets
      . biggest packet size
    */
    pcap_cfgs = malloc(sizeof(*pcap_cfgs) * opts.nb_traces);
    if (!pcap_cfgs) {
        log_error("malloc failed.");
        return (ENOMEM);
    }

    dpdk_cfgs = malloc(sizeof(*dpdk_cfgs) * opts.nb_traces);
    if (!dpdk_cfgs) {
        log_error("malloc failed.");
        return (ENOMEM);
    }
    
    for (int i = 0; i < opts.nb_traces; i++) {
        bzero(&pcap_cfgs[i], sizeof(pcap_cfgs[i]));
        bzero(&dpdk_cfgs[i], sizeof(dpdk_cfgs[i]));

        ret = preload_pcap(&opts, &pcap_cfgs[i], i);
        if (ret)
            goto mainExit;

        log_debug("Checking needed memory for pcap file %s", opts.traces[i].path);
        /* calculate needed memory to allocate for mempool */
        ret = check_needed_memory(&opts, &pcap_cfgs[i], &dpdk_cfgs[i]);
        if (ret)
            goto mainExit;
        
        log_debug("\n----------------------\n");
    }

    /*
      check that we have enough cpus, find the ones to use and calculate
       corresponding coremask
    */
    ret = init_cpus(&opts, &cpus);
    if (ret)
        goto mainExit;

    log_debug("Let's start to init DPDK EAL");

    /* init dpdk eal and mempool */
    ret = init_dpdk_eal_mempool(&opts, &cpus, dpdk_cfgs, opts.nb_traces);
    if (ret)
        goto mainExit;

    log_debug("Done init DPDK EAL");

    for (int i = 0; i < opts.nb_traces; i++) {
        /* cache pcap file into mempool */
        ret = load_pcap(&opts, &pcap_cfgs[i], &cpus, &dpdk_cfgs[i], 1);
        if (ret)
            goto mainExit;
    }

    /* init dpdk ports to send pkts */
    ret = init_dpdk_ports(&cpus, &opts, 1);
    if (ret)
        goto mainExit;

    /* Start all threads (PCAP and Stats) */
    ret = start_all_threads(&opts, &cpus, dpdk_cfgs, pcap_cfgs, opts.nb_traces);
    if (ret)
        goto mainExit;

mainExit:
    /* cleanup */
    log_trace("Cleaning up dpdk");
    /* close ethernet devices */
    for (int i = 0; i < rte_eth_dev_count_avail(); i++) {
        /* Check if the device is started */
        rte_eth_dev_stop(i);
        rte_eth_dev_close(i);
    }
    rte_eal_cleanup();

    log_trace("Cleaning up cpus");
    free(dpdk_cfgs);
    log_trace("Cleaning up pcap");
    free(pcap_cfgs);
    if (cpus.cpus_to_use) {
        log_trace("Cleaning up cpus_to_use");
        free(cpus.cpus_to_use);
    }
    return (ret);
}
