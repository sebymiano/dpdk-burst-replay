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

void usage(void)
{
    puts("dpdk-replay [OPTIONS] PCAP_FILE PORT1[,PORTX...]\n"
         "PCAP_FILE: the file to send through the DPDK ports.\n"
         "PORT1[,PORTX...] : specify the list of ports to be used (pci addresses).\n"
         "Options:\n"
         "--numacore <NUMA-CORE> : use cores from the desired NUMA. Only\n"
         "  NICs on the selected numa core will be available (default is 0).\n"
         "--nbruns <1-N> : set the wanted number of replay (1 by default).\n"
         "--wait-enter: will wait until you press ENTER to start the replay (asked"
         "  once all the initialization are done).\n"
         "--stats PORT1[,PORTX...]: specify the PCI address of the ports where to read the stats from\n"
         "--read-pci PORT1[,PORTX...]: set the PCI address of the ports where we only read data from (RX-only enabled)\n"
         "--timeout <1-N> : set the timeout in seconds\n"
         "--write-csv : if set write the statistics count on a csv file\n"
         /* TODO: */
         /* "[--maxbitrate bitrate]|[--normalspeed] : bitrate not to be exceeded (default: no limit) in ko/s.\n" */
         /* "  specify --normalspeed to replay the trace with the good timings." */
        );
    return ;
}

#ifdef DEBUG
void print_opts(const struct cmd_opts* opts)
{
    if (!opts)
        return ;
    puts("--");
    printf("numacore: %i\n", (int)(opts->numacore));
    printf("nb runs: %u\n", opts->nbruns);
    printf("timeout: %u\n", opts->timeout);
    printf("wait-enter: %s\n", opts->wait ? "yes" : "no");
    printf("write-csv: %s\n", opts->write_csv ? "yes" : "no");
    printf("slow-mode: %s\n", opts->slow_mode ? "yes" : "no");
    printf("max_mpps: %d\n", opts->max_mpps);

    printf("nb traces: %u\n", opts->nb_traces);
    for (int i = 0; i < opts->nb_traces; i++) {
        printf("trace[%d]: %s\n", i, opts->traces[i].path);
        printf("tx_queues[%d]: %d\n", i, opts->traces[i].tx_queues);
    }
    
    printf("pci nic ports:");
    for (int i = 0; i < opts->nb_pcicards; i++)
        printf(" %s", opts->pcicards[i]);

    for (int i = 0; i < opts->nb_stats; i++)
        printf("\nstats[%d]: %s\n", i, opts->stats[i]);

    for (int i = 0; i < opts->nb_stats_file_name; i++)
        printf("stats_name[%d]: %s\n", i, opts->stats_name[i]);
    
    puts("\n--");
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
        fprintf(stderr, "ERROR: %s\n", cyaml_strerror(err));
        return EXIT_FAILURE;
    }

    /* Check whether a pcap is set and the send port is set */
    if (cfg->traces_count == 0 || cfg->send_port_pci == NULL) {
        fprintf(stderr, "ERROR: You must specify at least one pcap file and the send port\n");
        return EXIT_FAILURE;
    }

    /* Assign traces to the opts struct */
    opts->traces = malloc(sizeof(trace_t) * cfg->traces_count);
    if (!opts->traces) {
        fprintf(stderr, "ERROR: Cannot allocate memory for traces\n");
        return EXIT_FAILURE;
    }
    for (int i = 0; i < cfg->traces_count; i++) {
        opts->traces[i].path = strdup(cfg->traces[i].path);
        opts->traces[i].tx_queues = cfg->traces[i].tx_queues;
    }
    opts->nb_traces = cfg->traces_count;

    /* Check whether the numa node is correct */
    if (cfg->numacore < 0 || cfg->numacore > 2) {
        fprintf(stderr, "ERROR: The NUMA node must be between 0 and 2\n");
        return EXIT_FAILURE;
    }
    opts->numacore = cfg->numacore;

    /* Check whether the number of runs is correct */
    if (cfg->nbruns <= 0) {
        fprintf(stderr, "ERROR: The number of runs must be greater than 0\n");
        return EXIT_FAILURE;
    }
    opts->nbruns = cfg->nbruns;

    /* Check whether the timeout is correct */
    if (cfg->timeout <= 0) {
        fprintf(stderr, "ERROR: The timeout must be greater than 0\n");
        return EXIT_FAILURE;
    }
    opts->timeout = cfg->timeout;

    if (cfg->max_mpps == -1) {
        fprintf(stderr, "Bitrate is UNLIMITED\n");
    }
    /* Check whether the max bitrate is correct */
    if (cfg->max_mpps < -1) {
        fprintf(stderr, "ERROR: The max bitrate must be greater than 0\n");
        return EXIT_FAILURE;
    }
    opts->max_mpps = cfg->max_mpps;

    cfg->wait_enter ? (opts->wait = 1) : (opts->wait = 0);
    cfg->write_csv ? (opts->write_csv = 1) : (opts->write_csv = 0);
    cfg->slow_mode ? (opts->slow_mode = 1) : (opts->slow_mode = 0);

    /* Check whether the stats ports are correct */
    if (cfg->stats_count > 0) {
        opts->stats = malloc(sizeof(char*) * cfg->stats_count);
        opts->stats_name = malloc(sizeof(char*) * cfg->stats_count);
        if (!opts->stats) {
            fprintf(stderr, "ERROR: Cannot allocate memory for stats ports\n");
            return EXIT_FAILURE;
        }
        for (int i = 0; i < cfg->stats_count; i++) {
            opts->stats[i] = strdup(cfg->stats[i].pci_id);
            opts->stats_name[i] = strdup(cfg->stats[i].file_name);
        }
        opts->nb_stats = cfg->stats_count;
        opts->nb_stats_file_name = cfg->stats_count;
    }

    /* Check whether the read ports are correct */
    if (cfg->send_port_pci != NULL) {
        /* TODO: In the future we should support more */
        unsigned int send_port_count = 1;
        opts->pcicards = malloc(sizeof(char*) * send_port_count);
        if (!opts->pcicards) {
            fprintf(stderr, "ERROR: Cannot allocate memory for read ports\n");
            return EXIT_FAILURE;
        }
        for (int i = 0; i < send_port_count; i++) {
            opts->pcicards[i] = strdup(cfg->send_port_pci);
        }
        opts->nb_pcicards = send_port_count;
        opts->nb_total_ports = send_port_count;
    }

    if (opts->nb_stats > 0) {
        for (int i = 0; opts->stats[i]; i++) {
            if (!str_in_list(opts->stats[i], opts->pcicards, opts->nb_pcicards)) {
                // If the device is already in the list of pci cards used for PCAP we don't count it
                opts->nb_total_ports += 1;
            }
        }
    }

    if (opts->nb_stats_file_name > 0 && opts->nb_stats_file_name != opts->nb_stats) {
        printf("You should provide the same number of file name and stats ports\n");
        return (EPROTO);
    }

    cyaml_free(&config, &top_schema, cfg, 0);

    return EXIT_SUCCESS;
}


int parse_options(const int ac, char** av, struct cmd_opts* opts)
{
    int i;

    if (!av || !opts)
        return (EINVAL);

    if (ac == 3) {
        if (!strcmp(av[1], "--config")) {
            printf("Parsing configuration file %s\n", av[2]);
            opts->config_file = av[2];
            if (parse_config_file(opts->config_file, opts) != 0) {
                return (EPROTO);
            } 
            return (0);
        }
    }

    /* if no trace or no pcicard is specified */
    if (ac < 3)
        return (ENOENT);

    for (i = 1; i < ac - 2; i++) {
        printf("av[%d] = %s\n", i, av[i]);
        /* --numacore numacore */
        if (!strcmp(av[i], "--numacore")) {
            int nc;

            /* if no numa core is specified */
            if (i + 1 >= ac - 2)
                return (ENOENT);

            nc = atoi(av[i + 1]);
            if (nc < 0 || nc > 2)
                return (ENOENT);
            opts->numacore = (char)nc;
            i++;
            continue;
        }

        /* --nbruns nbruns */
        if (!strcmp(av[i], "--nbruns")) {
            /* if no nb runs is specified */
            if (i + 1 >= ac - 2)
                return (ENOENT);
            opts->nbruns = atoi(av[i + 1]);
            if (opts->nbruns <= 0)
                return (EPROTO);
            i++;
            continue;
        }

        /* --wait-enter */
        if (!strcmp(av[i], "--wait-enter")) {
            opts->wait = 1;
            continue;
        }

        if (!strcmp(av[i], "--write-csv")) {
            opts->write_csv = 1;
            continue;
        }

        if (!strcmp(av[i], "--slow-mode")) {
            opts->slow_mode = 1;
            continue;
        }

        if (!strcmp(av[i], "--stats")) {
            opts->stats = str_to_stats_list(opts, av[i + 1]);
            i++;
            continue;
        }

        if (!strcmp(av[i], "--stats-name")) {
            opts->stats_name = str_to_stats_name_list(opts, av[i + 1]);
            i++;
            continue;
        }

        if (!strcmp(av[i], "--timeout")) {
            /* if no timeout is specified */
            if (i + 1 >= ac - 2)
                return (ENOENT);
            opts->timeout = atoi(av[i + 1]);
            if (opts->timeout <= 0)
                return (EPROTO);
            i++;
            continue;
        }

        break;
    }
    if (i + 2 > ac)
        return (EPROTO);

    opts->traces = malloc(sizeof(trace_t) * 1);
    if (!opts->traces)
        return (ENOMEM);

    opts->traces[0].path = strdup(av[i]);
    opts->traces[0].tx_queues = NB_TX_QUEUES;
    opts->nb_traces = 1;

    opts->pcicards = str_to_pcicards_list(opts, av[i + 1]);

    opts->nb_total_ports = opts->nb_pcicards;
    if (opts->nb_stats > 0) {
        for (int i = 0; opts->stats[i]; i++) {
            if (!str_in_list(opts->stats[i], opts->pcicards, opts->nb_pcicards)) {
                // If the device is already in the list of pci cards used for PCAP we don't count it
                opts->nb_total_ports += 1;
            }
        }
    }

    if (opts->nb_stats_file_name > 0 && opts->nb_stats_file_name != opts->nb_stats) {
        printf("You should provide the same number of file name and stats ports\n");
        return (EPROTO);
    }

    return (0);
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
#ifdef DEBUG
    puts("Needed paket allocation size = "
         "(size of MBUF) + (size of biggest pcap packet), "
         "rounded up to the next multiple of an integer.");
    printf("(%lu + %u) + ((%lu + %u) %% %lu) = %lu\n",
           sizeof(struct rte_mbuf), pcap->max_pkt_sz,
           sizeof(struct rte_mbuf), pcap->max_pkt_sz,
           sizeof(int), dpdk->mbuf_sz);
#endif /* DEBUG */
    printf("-> Needed MBUF size: %lu\n", dpdk->mbuf_sz);

    /* # CALCULATE THE NEEDED NUMBER OF MBUFS */
#ifdef DPDK_RECOMMANDATIONS
    /* For number of pkts to be allocated on the mempool, DPDK says: */
    /* The optimum size (in terms of memory usage) for a mempool is when n is a
       power of two minus one: n = (2^q - 1).  */
#ifdef DEBUG
    puts("Needed number of MBUFS: next power of two minus one of "
         "(nb pkts * nb ports)");
#endif /* DEBUG */
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
    printf("-> Needed number of MBUFS: %lu\n", dpdk->nb_mbuf);

    /* # CALCULATE THE TOTAL NEEDED MEMORY SIZE  */
    needed_mem = dpdk->mbuf_sz * dpdk->nb_mbuf;
#ifdef DEBUG
    puts("Needed memory = (needed mbuf size) * (number of needed mbuf).");
    printf("%lu * %lu = %.0f bytes\n", dpdk->mbuf_sz, dpdk->nb_mbuf, needed_mem);
#endif /* DEBUG */
    hsize = nb_oct_to_human_str(needed_mem);
    if (!hsize)
        return (-1);
    printf("-> Needed Memory = %s\n", hsize);
    free(hsize);

    /* # CALCULATE THE NEEDED NUMBER OF GIGABYTE HUGEPAGES */
    if (fmod(needed_mem,((double)(1024*1024*1024))))
        dpdk->pool_sz = needed_mem / (float)(1024*1024*1024) + 1;
    else
        dpdk->pool_sz = needed_mem / (1024*1024*1024);
    printf("-> Needed Hugepages of 1 Go = %lu\n", dpdk->pool_sz);
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
    
#ifdef DEBUG
    print_opts(&opts);
#endif /* DEBUG */

    /*
      pre parse the pcap file to get needed informations:
      . number of packets
      . biggest packet size
    */
    pcap_cfgs = malloc(sizeof(*pcap_cfgs) * opts.nb_traces);
    if (!pcap_cfgs) {
        printf("%s: malloc failed.\n", __FUNCTION__);
        return (ENOMEM);
    }

    dpdk_cfgs = malloc(sizeof(*dpdk_cfgs) * opts.nb_traces);
    if (!dpdk_cfgs) {
        printf("%s: malloc failed.\n", __FUNCTION__);
        return (ENOMEM);
    }
    
    for (int i = 0; i < opts.nb_traces; i++) {
        bzero(&pcap_cfgs[i], sizeof(pcap_cfgs[i]));
        bzero(&dpdk_cfgs[i], sizeof(dpdk_cfgs[i]));

        ret = preload_pcap(&opts, &pcap_cfgs[i], i);
        if (ret)
            goto mainExit;

        printf("Checking needed memory for pcap file %s\n", opts.traces[i].path);
        /* calculate needed memory to allocate for mempool */
        ret = check_needed_memory(&opts, &pcap_cfgs[i], &dpdk_cfgs[i]);
        if (ret)
            goto mainExit;
        
        printf("\n----------------------\n");
    }

    /*
      check that we have enough cpus, find the ones to use and calculate
       corresponding coremask
    */
    ret = init_cpus(&opts, &cpus);
    if (ret)
        goto mainExit;

    /* init dpdk eal and mempool */
    ret = init_dpdk_eal_mempool(&opts, &cpus, dpdk_cfgs, opts.nb_traces);
    if (ret)
        goto mainExit;

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
    for (int i = 0; i < opts.nb_traces; i++) {
        clean_pcap_ctx(&pcap_cfgs[i]);
        dpdk_cleanup(&dpdk_cfgs[i], &cpus);
    }
    free(dpdk_cfgs);
    free(pcap_cfgs);
    if (cpus.cpus_to_use)
        free(cpus.cpus_to_use);
    return (ret);
}
