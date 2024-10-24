/*
  SPDX-License-Identifier: BSD-3-Clause
  Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.
*/

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <linux/limits.h>

/* DPDK includes */
#include <rte_version.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <rte_time.h>
#include <pthread.h>

#include "main.h"
#include "argparse.h"

#define IFG_PLUS_PREAMBLE 20

enum {
    INTER_FRAME_GAP       = 12, /**< in bytes */
    START_FRAME_DELIMITER = 1,
    PKT_PREAMBLE_SIZE     = 7, /**< in bytes */
    PKT_OVERHEAD_SIZE = (INTER_FRAME_GAP + START_FRAME_DELIMITER + PKT_PREAMBLE_SIZE + RTE_ETHER_CRC_LEN),
};

#define Million            (uint64_t)(1000000UL)
#define Billion            (uint64_t)(1000000000UL)

static struct rte_eth_conf port_conf_default = {
#ifdef RTE_VER_YEAR
    #if API_AT_LEAST_AS_RECENT_AS(22, 03)
    /* version  > to 2.2.0, last one with old major.minor.patch system */
    .link_speeds = RTE_ETH_LINK_SPEED_FIXED,
    #else
    .link_speeds = ETH_LINK_SPEED_FIXED,
    #endif
#else
    /* compatibility with older version */
    .link_speed = 0,        // autonegociated speed link
    .link_duplex = 0,       // autonegociated link mode
#endif
    .rxmode = {
        #if API_AT_LEAST_AS_RECENT_AS(22, 03)
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        #else
        .mq_mode = ETH_MQ_RX_RSS,
        #endif
    },

    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },

    .txmode = {
        #if API_AT_LEAST_AS_RECENT_AS(22, 03)
        .mq_mode = RTE_ETH_MQ_TX_NONE,  // Multi queue packet routing mode.
        #else
        .mq_mode = ETH_MQ_TX_NONE,      // Multi queue packet routing mode.
        #endif
    },

    .intr_conf = {
        .lsc = 0,                   // Disable lsc interrupts
    },
};

static struct rte_eth_txconf const txconf = {
    .tx_thresh = {
        .pthresh = TX_PTHRESH,
        .hthresh = TX_HTHRESH,
        .wthresh = TX_WTHRESH,
    },
    .tx_free_thresh = 32,
};

pthread_mutex_t log_mutex; // Mutex for logging

void* myrealloc(void* ptr, size_t new_size)
{
    void* res = realloc(ptr, new_size);
    if (!res && ptr)
        free(ptr);
    return (res);
}

char** fill_eal_args(const struct cmd_opts* opts, const struct cpus_bindings* cpus,
                     const struct dpdk_ctx* dpdk, int* eal_args_ac)
{
    char    buf_coremask[30];
    char    file_prefix[30];
    char**  eal_args;
    int     i, cpt;

    if (!opts || !cpus || !dpdk)
        return (NULL);

    int current_pid = getpid();
    /* Set EAL init parameters */
    snprintf(buf_coremask, 20, "0x%016lX", cpus->coremask);
    snprintf(file_prefix, 20, "dpdkreplay_%d", current_pid);
    char *pre_eal_args[] = {
        "./dpdk-replay",
        "-c", strdup(buf_coremask),
        "-n", "1", /* NUM MEM CHANNELS */
        "--proc-type", "auto",
        "--file-prefix", strndup(file_prefix, strlen(file_prefix)),
        NULL
    };
    
    /* fill pci whitelist args */
    eal_args = malloc(sizeof(*eal_args) * sizeof(pre_eal_args));
    if (!eal_args)
        return (NULL);
    memcpy(eal_args, (char**)pre_eal_args, sizeof(pre_eal_args));
    cpt = sizeof(pre_eal_args) / sizeof(*pre_eal_args);

    log_debug("nb pci cards: %d", opts->nb_pcicards);
    
    for (i = 0; i < opts->nb_pcicards; i++) {
        eal_args = myrealloc(eal_args, sizeof(char*) * (cpt + 2));
        if (!eal_args)
            return (NULL);
        // eal_args[cpt - 1] = "--pci-whitelist"; /* overwrite "NULL" */
        eal_args[cpt - 1] = "--allow"; /* overwrite "NULL" */
        log_debug("Adding PCI card: %s", opts->pcicards[i]);
        eal_args[cpt] = opts->pcicards[i];
        eal_args[cpt + 1] = NULL;
        cpt += 2;
    }

    // log_debug("Fone");

    if (opts->nb_stats > 0) {
        // If we setup a device to read packets from
        for (i = 0; i < opts->nb_stats; i++) {
            if (str_in_list(opts->stats[i], opts->pcicards, opts->nb_pcicards)) {
                // If the device is already in the list of pci cards used for PCAP we don't need this
                continue;
            }
            eal_args = myrealloc(eal_args, sizeof(char*) * (cpt + 2));
            if (!eal_args)
                return (NULL);
            eal_args[cpt - 1] = "--allow"; /* overwrite "NULL" */
            eal_args[cpt] = opts->stats[i];
            eal_args[cpt + 1] = NULL;
            cpt += 2;
        }
    }

    *eal_args_ac = cpt - 1;
    return (eal_args);
}

static struct rte_mempool *
dpdk_mbuf_pool_create(const char *type, uint8_t pid, uint8_t queue_id,
			uint32_t nb_mbufs, int socket_id, int cache_size){
	struct rte_mempool *mp;
	char name[RTE_MEMZONE_NAMESIZE];
	uint64_t sz;

	snprintf(name, sizeof(name), "%-12s%u:%u", type, pid, queue_id);
    log_trace("Creating mbuf pool: %s", name);

	sz = nb_mbufs * (DEFAULT_MBUF_SIZE + sizeof(struct rte_mbuf));
	sz = RTE_ALIGN_CEIL(sz + sizeof(struct rte_mempool), 1024);

	/* create the mbuf pool */
	mp = rte_pktmbuf_pool_create(name, nb_mbufs, cache_size, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
	if (mp == NULL)
		log_error(
			"Cannot create mbuf pool (%s) port %d, queue %d, nb_mbufs %d, socket_id %d: %s",
			name, pid, queue_id, nb_mbufs, socket_id, rte_strerror(rte_errno));

	return mp;
}


int dpdk_init_rx_queues(struct cpus_bindings* cpus, int port, unsigned int num_rx_queues) {
    int                 ret, i;
    struct rte_eth_dev_info dev_info;     /**< PCI info + driver name */

    uint16_t nb_txd = 0;
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);

    if (ret < 0) {
        log_error( "rte_eth_dev_adjust_nb_rx_tx_desc: err=%d, port=%d", ret, port);
        return (-1);
    }

    log_trace("Adjusted nb_rxd=%u, nb_txd=%u for port %d", nb_rxd, nb_txd, port);

    struct rte_mempool *mp = dpdk_mbuf_pool_create("Default RX", port, 0, NUM_MBUFS, 
                                    cpus->numacore, MEMPOOL_CACHE_SIZE);

    /* Then allocate and set up the rx queues for this Ethernet device  */
    for (int q = 0; q < num_rx_queues; q++) {
        struct rte_eth_rxconf rxq_conf;

        // cpus->q[port][q].rx_mp = dpdk_mbuf_pool_create("Default RX", port, q, NUM_MBUFS, 
        //                             cpus->numacore, MEMPOOL_CACHE_SIZE);
        cpus->q[port][q].rx_mp = mp;
        if (cpus->q[port][q].rx_mp == NULL) {
            log_error("Cannot init mbuf pool (port %u)", port);
            return (-1);
        }
        
        // rxq_conf = dev_info.default_rxconf;
        ret = rte_eth_rx_queue_setup(port, q, nb_rxd, cpus->numacore,
						             NULL, cpus->q[port][q].rx_mp);

        if (ret < 0) {
            log_error("DPDK: RTE ETH Ethernet device RX queue %i setup failed: %s",
                    i, strerror(-ret));
            return (ret);
        }
    }

    ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0) {
        log_error("Error during getting device (port %u) info: %s", port, strerror(-ret));
        return (-1);
    }

    log_trace("Port %d: RX queues %d, max nb_rxd %d", port, dev_info.max_rx_queues, dev_info.rx_desc_lim.nb_max);
    log_trace("Port %d: TX queues %d, max nb_txd %d", port, dev_info.max_tx_queues, dev_info.tx_desc_lim.nb_max);

    return 0;
}

int dpdk_init_port(struct cpus_bindings* cpus, int port, unsigned int num_rx_queues, unsigned int num_tx_queues)
{
    int                 ret, i;
    struct rte_eth_link eth_link;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf = port_conf_default;

    if (!cpus)
        return (EINVAL);

    if (!rte_eth_dev_is_valid_port(port)) {
        log_error("DPDK: Invalid port %d", port);
        return (-1);
    }

    ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0) {
        log_error("Error during getting device (port %u) info: %s", port, strerror(-ret));
        return (-ret);
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
    if (port_conf.rx_adv_conf.rss_conf.rss_hf != port_conf_default.rx_adv_conf.rss_conf.rss_hf) {
        log_info("Port %u modified RSS hash function based on hardware support,"
            "requested:%#"PRIx64" configured:%#"PRIx64"\n",
            port,
            port_conf_default.rx_adv_conf.rss_conf.rss_hf,
            port_conf.rx_adv_conf.rss_conf.rss_hf);
    }

    /* Configure for each port (ethernet device), the number of rx queues & tx queues */
    log_info("Configuring port %d with %d rx queues and %d tx queues", port, num_rx_queues, num_tx_queues);
    if (rte_eth_dev_configure(port,
                              num_rx_queues, /* nb rx queue */
                              num_tx_queues, /* nb tx queue */
                              &port_conf) < 0) {
        log_error("DPDK: RTE ETH Ethernet device configuration failed");
        return (-1);
    }

    /* Then allocate and set up the transmit queues for this Ethernet device  */
    for (i = 0; i < num_tx_queues; i++) {
        ret = rte_eth_tx_queue_setup(port,
                                     i,
                                     TX_QUEUE_SIZE,
                                     cpus->numacore,
                                     &txconf);
        if (ret < 0) {
            log_error("DPDK: RTE ETH Ethernet device tx queue %i setup failed: %s",
                    i, strerror(-ret));
            return (ret);
        }
    }

    if (dpdk_init_rx_queues(cpus, port, num_rx_queues) != 0) {
        log_error("DPDK: Error during initialization of RX queues for port %d", port);
        return (-1);
    }

    /* Start the ethernet device */
    if (rte_eth_dev_start(port) < 0) {
        log_error("DPDK: RTE ETH Ethernet device start failed");
        return (-1);
    }

    ret = rte_eth_promiscuous_enable(port);

    if (ret) {
        log_error("DPDK: Failed to enable promiscous mode on port: %d", port);
        return (-1);
    }

    /* Get link status and display it. */
    rte_eth_link_get(port, &eth_link);
    if (eth_link.link_status) {
    #if API_AT_LEAST_AS_RECENT_AS(22, 03)
        log_info(" Link up - speed %u Mbps - %s",
               eth_link.link_speed,
               (eth_link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
               "full-duplex" : "half-duplex");
    #else 
        log_info(" Link up - speed %u Mbps - %s",
               eth_link.link_speed,
               (eth_link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
               "full-duplex" : "half-duplex");
    #endif
    } else {
        log_info("Link down");
    }

    return (0);
}


int dpdk_init_read_port(struct cpus_bindings* cpus, int port, unsigned int num_rx_queues, unsigned int num_tx_queues)
{
    int                 ret, i;
    struct rte_eth_dev_info dev_info;     /**< PCI info + driver name */
    struct rte_eth_conf local_port_conf = port_conf_default;

    /* Configure for each port (ethernet device), the number of rx queues & tx queues */
    if (rte_eth_dev_configure(port,
                              num_rx_queues, /* nb rx queue */
                              0, /* nb tx queue */
                              &local_port_conf) < 0) {
        log_error("DPDK: RTE ETH Ethernet device configuration failed");
        return (-1);
    }

    if (dpdk_init_rx_queues(cpus, port, num_rx_queues) != 0) {
        log_error("DPDK: Error during initialization of RX queues for port %d", port);
        return (-1);
    }

    /* Start the ethernet device */
    if (rte_eth_dev_start(port) < 0) {
        log_error("DPDK: RTE ETH Ethernet device start failed");
        return (-1);
    }

    ret = rte_eth_promiscuous_enable(port);
    if (ret) {
        log_error("DPDK: Failed to enable promiscous mode on port: %d", port);
        return (-1);
    }

    return (0);
}

int init_dpdk_eal_mempool(const struct cmd_opts* opts,
                          const struct cpus_bindings* cpus,
                          struct dpdk_ctx* dpdk_cfgs, unsigned int pcap_num)
{
    char**          eal_args;
    int             eal_args_ac = 0;
    unsigned int    nb_ports;
    int             ret;

    if (!opts || !cpus || !dpdk_cfgs)
        return (EINVAL);

    /* API BREAKAGE ON 17.05 */
#if API_OLDEST_THAN(17, 05)
    rte_set_log_level(RTE_LOG_ERR);
#else /* if DPDK >= 17.05 */
    rte_log_set_global_level(RTE_LOG_ERR);
#endif
    log_debug("Filling eal args");
    /* craft an eal arg list */
    eal_args = fill_eal_args(opts, cpus, &dpdk_cfgs[0], &eal_args_ac);
    if (!eal_args) {
        log_error("fill_eal_args failed.");
        return (1);
    }

    log_debug("EAL ARGS:");
    for (int i = 0; eal_args[i]; i++)
        log_debug("eal_args[%i] = %s", i, eal_args[i]);

    /* DPDK RTE EAL INIT */
    ret = rte_eal_init(eal_args_ac, eal_args);
    free(eal_args);
    if (ret < 0) {
        log_error("rte_eal_init failed (%d)", ret);
        return (ret);
    }

    /* check that dpdk see enough usable cores */
    if (rte_lcore_count() != cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus + 1) {
        log_error("error: not enough rte_lcore founds");
        log_error("Required: %d, obtained: %d", cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus + 1, rte_lcore_count());
        return (1);
    }

    /* check that dpdk detects all wanted/needed NIC ports */
#if API_OLDEST_THAN(18, 05) /* API BREAKAGE ON 18.05 */
    nb_ports = rte_eth_dev_count();
#else /* if DPDK >= 18.05 */
    nb_ports = rte_eth_dev_count_avail();
#endif
    if (nb_ports != opts->nb_total_ports) {
        log_error("error: wanted %u NIC ports, found %u", opts->nb_total_ports, nb_ports);
        return (1);
    }

    for (int i = 0; i < opts->nb_traces; i++) {
        log_info("-> Create mempool of %lu mbufs of %lu octs.", dpdk_cfgs[i].nb_mbuf, dpdk_cfgs[i].mbuf_sz);
        char mempool_name[PATH_MAX];
        snprintf(mempool_name, sizeof(mempool_name), "dpdk_replay_mempool_%d", i);
        dpdk_cfgs[i].pktmbuf_pool = rte_mempool_create(mempool_name,
                                            dpdk_cfgs[i].nb_mbuf,
                                            dpdk_cfgs[i].mbuf_sz,
                                            MBUF_CACHE_SZ,
                                            sizeof(struct rte_pktmbuf_pool_private),
                                            rte_pktmbuf_pool_init, NULL,
                                            rte_pktmbuf_init, NULL,
                                            cpus->numacore,
                                            0);
        if (dpdk_cfgs[i].pktmbuf_pool == NULL) {
            log_error("DPDK: RTE Mempool creation failed (%s)",
                    rte_strerror(rte_errno));
    #if API_AT_LEAST_AS_RECENT_AS(18, 05)
            if (rte_errno == ENOMEM
                && (dpdk_cfgs[i].nb_mbuf * dpdk_cfgs[i].mbuf_sz /1024/1024) > RTE_MAX_MEM_MB_PER_LIST)
                log_error("Your version of DPDK was configured to use at maximum"
                        " %u Mo, or you try to allocate ~%lu Mo."
                        "Try to recompile DPDK by setting CONFIG_RTE_MAX_MEM_MB_PER_LIST"
                        " according to your needs.", RTE_MAX_MEM_MB_PER_LIST,
                        dpdk_cfgs[i].nb_mbuf * dpdk_cfgs[i].mbuf_sz /1024/1024);
    #endif /* API_AT_LEAST_AS_RECENT_AS(18, 05) */
            return (rte_errno);
        }
    }

    
    return (0);
}

int init_dpdk_ports(struct cpus_bindings* cpus, const struct cmd_opts* opts, unsigned int needed_cpus)
{
    int i;
    int numa;

    if (!cpus)
        return (EINVAL);

    unsigned int num_tx_queues = 0;
    unsigned int num_rx_queues = opts->nb_rx_queues;

    for (i = 0; i < opts->nb_traces; i++) {
        num_tx_queues += opts->traces[i].tx_queues;
    }

    for (i = 0; (unsigned)i < needed_cpus; i++) {
        /* if the port ID isn't on the good numacore, exit */
        numa = rte_eth_dev_socket_id(i);
        if (numa != cpus->numacore) {
            log_error("port %i is not on the good numa id (%i).", i, numa);
            return (1);
        }
        /* init ports */
        if (dpdk_init_port(cpus, i, num_rx_queues, num_tx_queues))
            return (1);
        log_info("-> NIC port %i ready.", i);
    }

    // Now if I have a device to read packets from I need to setup the corresponding port
    for (i = needed_cpus; (unsigned)i < (opts->nb_total_ports); i++) {
        /* if the port ID isn't on the good numacore, exit */
        numa = rte_eth_dev_socket_id(i);
        if (numa != cpus->numacore) {
            log_error("port %i is not on the good numa id (%i).", i, numa);
            return (1);
        }
        /* init ports */
        if (dpdk_init_read_port(cpus, i, num_rx_queues, 0))
            return (1);
        log_info("-> NIC port %i (for read) ready.", i);
    }

    return (0);
}

double timespec_diff_to_double(const struct timespec start, const struct timespec end)
{
    struct timespec diff;
    double duration;

    diff.tv_sec = end.tv_sec - start.tv_sec;
    if (end.tv_nsec > start.tv_nsec)
        diff.tv_nsec = end.tv_nsec - start.tv_nsec;
    else {
        diff.tv_nsec = end.tv_nsec - start.tv_nsec + 1000000000;
        diff.tv_sec--;
    }
    duration = diff.tv_sec + ((double)diff.tv_nsec / 1000000000);
    return (duration);
}

static uint64_t create_timestamp(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return rte_timespec_to_ns(&now);
}

/* Calculate the number of cycles to wait between sending bursts of traffic. */
uint64_t get_tx_cycles_mpps(const struct cmd_opts* opts) {
    double pps         = opts->max_mpps * Million;
    uint64_t cpp       = (pps > 0) ? (rte_get_timer_hz() / pps) : rte_get_timer_hz();
    uint64_t tx_cycles = (cpp * BURST_SZ);

    log_debug("pps: %.2f, cpp: %lu, tx_cycles: %lu", pps, cpp, tx_cycles);

    return tx_cycles;
}

uint64_t get_tx_cycles_mbps(const struct pcap_ctx* pcap_cfgs, const struct cmd_opts* opts) {
    uint64_t wire_size = (pcap_cfgs->avg_pkt_sz + PKT_OVERHEAD_SIZE) * 8;
    
    double link_bps       = opts->max_mbps * Million;
    uint64_t id_cycles = (wire_size / link_bps) * rte_get_timer_hz();
    uint64_t tx_cycles = (id_cycles * BURST_SZ);

    log_debug("wire_size: %lu, lk: %.2f, cpp: %lu, tx_cycles: %lu", wire_size, link_bps, id_cycles, tx_cycles);

    return tx_cycles;
}

int remote_thread(void* thread_ctx)
{
    struct thread_ctx*  ctx;
    struct rte_mbuf**   mbuf;
    struct timespec     start, end;
    unsigned int        tx_queue;
    int                 ret, thread_id, index, i, run_cpt, retry_tx;
    int                 nb_sent, to_sent, total_to_sent, total_sent;
    int                 nb_drop;
    int        sem_value;

    if (!thread_ctx)
        return (EINVAL);

    /* retrieve thread context */
    ctx = (struct thread_ctx*)thread_ctx;

    thread_id = ctx->thread_id;

    if (ctx->t_type == PCAP_THREAD) {
        log_trace("[Thread %d] This thread is a TX thread", thread_id);
        log_trace("[Thread %d] RX port id: %d, TX port id: %d", thread_id, ctx->rx_port_id, ctx->tx_port_id);
        log_debug("[Thread %d] NB TX queues: %i", thread_id, ctx->nb_tx_queues);
        log_debug("[Thread %d] NB TX queues start: %i", thread_id, ctx->nb_tx_queues_start);
        log_debug("[Thread %d] NB TX queues end: %i", thread_id, ctx->nb_tx_queues_end);

        log_info("[Thread %d] Sending PCAP trace. Wait %d seconds", thread_id, ctx->timeout);
    } else if (ctx->t_type == STATS_THREAD) {
        log_trace("[Thread %d] This thread is a STATS thread", thread_id);
        log_trace("[Thread %d] RX port id: %d, TX port id: %d", thread_id, ctx->rx_port_id, ctx->tx_port_id);
    } else if (ctx->t_type == RECV_THREAD) {
        log_trace("[Thread %d] This thread is a RX thread", thread_id);
        log_trace("[Thread %d] RX port id: %d, TX port id: %d", thread_id, ctx->rx_port_id, ctx->tx_port_id);
        log_debug("[Thread %d] NB RX queues: %i", thread_id, ctx->nb_rx_queues);
        log_debug("[Thread %d] NB RX queues start: %i", thread_id, ctx->nb_rx_queues_start);
        log_debug("[Thread %d] NB RX queues end: %i", thread_id, ctx->nb_rx_queues_end);
    } else {
        log_error("Thread type not recognized");
        return (EINVAL);
    }

    /* init semaphore to wait to start the burst */
    ret = sem_wait(ctx->sem);
    if (ret) {
        log_error("sem_wait failed on thread %i: %s",
                thread_id, strerror(ret));
        return (ret);
    }

    /* get the start time */
    ret = clock_gettime(CLOCK_MONOTONIC, &start);
    if (ret) {
        log_error("clock_gettime failed on start for thread %i: %s",
                thread_id, strerror(errno));
        return (errno);
    }

    if (ctx->t_type == PCAP_THREAD) {
        mbuf = ctx->pcap_cache->mbufs;
        bool wait_tx_rate = true;
        unsigned int retry_tx_cfg = ctx->nb_tx_queues * 2;
        if (ctx->tx_rate_cycles == -1) {
            wait_tx_rate = false;
        }
        // Calculate the time interval between packet sends based on desired rate
        uint64_t tx_next_cycle, curr_tsc;

        /* iterate on each wanted runs */
        for (run_cpt = ctx->nbruns, tx_queue = ctx->nb_tx_queues_start, ctx->total_drop = ctx->total_drop_sz = 0; run_cpt; ctx->total_drop += nb_drop, run_cpt--) {
            if (wait_tx_rate) {
                curr_tsc = rte_get_tsc_cycles();
                tx_next_cycle = curr_tsc;
                // printf("tx_next_cycle: %ld", tx_next_cycle);
            }
            /* iterate on pkts for every batch of BURST_SZ number of packets */
            for (total_to_sent = ctx->nb_pkt, nb_drop = 0, to_sent = min(BURST_SZ, total_to_sent);
                to_sent;
                total_to_sent -= to_sent, to_sent = min(BURST_SZ, total_to_sent)) {
                /* calculate the mbuf index for the current batch */
                index = ctx->nb_pkt - total_to_sent;

                /* send the burst batch, and retry NB_RETRY_TX times if we */
                /* didn't success to sent all the wanted batch */
                for (total_sent = 0, retry_tx = retry_tx_cfg;
                    total_sent < to_sent && retry_tx;
                    total_sent += nb_sent, retry_tx--) {
                    if (wait_tx_rate) {
                        curr_tsc = rte_get_tsc_cycles();
                        tx_next_cycle += ctx->tx_rate_cycles;
                        if (curr_tsc < tx_next_cycle) {
                            uint64_t wait_cycles = tx_next_cycle - curr_tsc;
                            uint64_t wait_us = (wait_cycles * 1000000) / rte_get_timer_hz();
                            // printf("Wait for: %ldus", wait_us);
                            rte_delay_us(wait_us);
                        }
                    }
                    nb_sent = rte_eth_tx_burst(ctx->tx_port_id,
                                            tx_queue,
                                            &(mbuf[index + total_sent]),
                                            to_sent - total_sent);
                    // printf("[Thread %d] Sent %d packets", thread_id, nb_sent);
                    if (retry_tx != retry_tx_cfg &&
                        tx_queue % ctx->nb_tx_queues_end == 0)
                        usleep(100);

                    if (tx_queue >= ctx->nb_tx_queues_end) {
                        tx_queue = ctx->nb_tx_queues_start;
                    } else {
                        tx_queue++;
                    }
                }
                /* free unseccessfully sent  */
                if (unlikely(!retry_tx))
                    for (i = total_sent; i < to_sent; i++) {
                        nb_drop++;
                        ctx->total_drop_sz += mbuf[index + i]->pkt_len;
                        rte_pktmbuf_free(mbuf[index + i]);
                    }
            }
            if (unlikely(nb_drop))
                log_trace("[thread %i]: on loop %i: sent %i pkts (%i were dropped).",
                    thread_id, ctx->nbruns - run_cpt, ctx->nb_pkt, nb_drop);


            sem_getvalue(ctx->sem_stop, &sem_value);
            if (sem_value > 0) {
                break;
            }

            if (ctx->slow_mode) {
                // TODO: Better control of sending rate in the future
                sleep(1);
            }
        }
    } else if (ctx->t_type == STATS_THREAD) {
        struct rte_eth_stats  old_stats; 
        struct rte_eth_stats  stats;

        uint64_t   diff_cycles;
        uint64_t   prev_cycles = rte_get_tsc_cycles();

        uint64_t   rx_pkt_delta = 0;
        uint64_t   rx_bytes_delta = 0;
        uint64_t   rx_bit_delta = 0;
        uint64_t   rx_pkt_rate = 0;
        uint64_t   rx_bytes_rate = 0;

        uint64_t   tx_pkt_delta = 0;
        uint64_t   tx_bytes_delta = 0;
        uint64_t   tx_pkt_rate = 0;
        uint64_t   tx_bytes_rate = 0;
        uint64_t   tx_bit_delta = 0;

        double gbps = 0.0;
        bzero(&old_stats, sizeof(old_stats));
        run_cpt = 0;
        // If we have the CSV file flag enable, let's write the CSV header
        if (ctx->csv_ptr) {
            fprintf(ctx->csv_ptr, "#Port,Time,RX-packets,RX-bytes,TX-packets,TX-bytes\n");
        }

        while (true) {
            run_cpt++;
            rte_eth_stats_get(ctx->rx_port_id, &stats);
            if (ret) {
                log_error("Error while reading stats from port: %u", ctx->rx_port_id);
                sleep(1);
                continue;
            }
            diff_cycles = prev_cycles;
            prev_cycles = rte_get_tsc_cycles();
            if (diff_cycles > 0)
                diff_cycles = prev_cycles - diff_cycles;

            rx_pkt_delta = stats.ipackets - old_stats.ipackets;
            rx_pkt_rate = diff_cycles > 0 ? (rx_pkt_delta * rte_get_tsc_hz()) / diff_cycles : 0;

            rx_bytes_delta = stats.ibytes - old_stats.ibytes;
            rx_bit_delta = (rx_bytes_delta + (PKT_OVERHEAD_SIZE * rx_pkt_delta)) * 8;
            rx_bytes_rate =  diff_cycles > 0 ? (rx_bytes_delta * rte_get_tsc_hz()) / diff_cycles : 0;

            tx_pkt_delta = stats.opackets - old_stats.opackets;
            tx_pkt_rate =  diff_cycles > 0 ? (tx_pkt_delta * rte_get_tsc_hz()) / diff_cycles : 0;

            tx_bytes_delta = stats.obytes - old_stats.obytes;
            tx_bit_delta = (tx_bytes_delta + (PKT_OVERHEAD_SIZE * tx_pkt_delta)) * 8;
            tx_bytes_rate =  diff_cycles > 0 ? (tx_bytes_delta * rte_get_tsc_hz()) / diff_cycles : 0;

            log_info("[Thread %d]: -> Stats for port: %u\n", thread_id, ctx->rx_port_id);
            gbps =  (double)(rx_bit_delta)/Billion;
            // Print stats with 2 decimal places
            log_info("  RX-packets: %-10"PRIu64"  RX-bytes:  %-10"PRIu64"  RX-Gbps: %.2f", 
                    rx_pkt_rate,
                    rx_bytes_rate,
                    gbps);
            gbps =  (double)(tx_bit_delta)/Billion;
            log_info("  TX-packets: %-10"PRIu64"  TX-bytes:  %-10"PRIu64"  TX-Gbps: %.2f", 
                    tx_pkt_rate, 
                    tx_bytes_rate,
                    gbps);
            log_info("\n");

            memcpy(&old_stats, &stats, sizeof(stats));
            if (ctx->csv_ptr) {
                fprintf(ctx->csv_ptr, "%u,%u,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n", 
                                      ctx->rx_port_id, run_cpt,
                                      rx_pkt_rate, rx_bytes_rate,
                                      tx_pkt_rate, tx_bytes_rate);
            }
            sleep(1);
            
            sem_getvalue(ctx->sem_stop, &sem_value);
            if (sem_value > 0) {
                break;
            }
        }
    } else if (ctx->t_type == RECV_THREAD) {
        // We are in the receive thread        
        uint16_t nb_rx;
        for (;;) {
            struct rte_mbuf *bufs[64];
            for (int q = ctx->nb_rx_queues_start; q <= ctx->nb_rx_queues_end; q++) {
                nb_rx = rte_eth_rx_burst(ctx->rx_port_id, q, bufs, 64);
                // log_trace("[Thread %d] RX queue %d, received %d packets", thread_id, q, nb_rx);
                if (unlikely(nb_rx == 0))
                    continue;

                rte_pktmbuf_free_bulk(bufs, nb_rx);
            }

            sem_getvalue(ctx->sem_stop, &sem_value);
            if (sem_value > 0) {
                break;
            }
        }
    } else {
        log_error("Thread type not recognized");
        return (EINVAL);
    }

    /* get the ends time and calculate the duration */
    ret = clock_gettime(CLOCK_MONOTONIC, &end);
    if (ret) {
        log_error("clock_gettime failed on finish for thread %i: %s",
                thread_id, strerror(errno));
        return (errno);
    }
    ctx->duration = timespec_diff_to_double(start, end);

    log_debug("Exiting thread %i properly.", thread_id);

    return (0);
}

int process_result_stats(const struct cpus_bindings* cpus,
                         const struct dpdk_ctx* dpdk_cfgs,
                         const struct cmd_opts* opts,
                         const struct thread_ctx* ctx)
{
    double              pps, bitrate;
    double              total_pps, total_bitrate;
    unsigned long int   total_pkt_sent, total_pkt_sent_sz;
    unsigned int        i, total_drop, total_pkt;

    if (!cpus || !dpdk_cfgs || !opts || !ctx)
        return (EINVAL);

    total_pps = total_bitrate = 0;
    total_drop = 0;
    log_info("RESULTS :");
    for (i = 0; i < cpus->nb_needed_pcap_cpus; i++) {
        total_pkt_sent = (ctx[i].nb_pkt * opts->nbruns) - ctx[i].total_drop;
        total_pkt_sent_sz = (dpdk_cfgs[i].pcap_sz * opts->nbruns) - ctx[i].total_drop_sz;
        pps = total_pkt_sent / ctx[i].duration;
        bitrate = total_pkt_sent_sz / ctx[i].duration
            * 8 /* Bytes to bits */
            / 1024 /* bits to Kbits */
            / 1024 /* Kbits to Mbits */
            / 1024; /* Mbits to Gbits */
        total_bitrate += bitrate;
        total_pps += pps;
        total_drop += ctx[i].total_drop;
        log_info("[thread %02u]: %f Gbit/s, %f pps on %f sec (%u pkts dropped)",
               i, bitrate, pps, ctx[i].duration, ctx[i].total_drop);
    }
    log_info("-----");
    log_info("TOTAL        : %.3f Gbit/s. %.3f pps.", total_bitrate, total_pps);
    total_pkt = ctx[0].nb_pkt * opts->nbruns * cpus->nb_needed_pcap_cpus;
    log_info("Total dropped: %u/%u packets (%f%%)", total_drop, total_pkt,
           (double)(total_drop * 100) / (double)(total_pkt));
    return (0);
}

void log_lock_function(bool lock, void *lock_arg) {
    if (lock) {
        pthread_mutex_lock((pthread_mutex_t *) lock_arg);
    } else {
        pthread_mutex_unlock((pthread_mutex_t *) lock_arg);
    }
}


int start_all_threads(const struct cmd_opts* opts,
                     const struct cpus_bindings* cpus,
                     const struct dpdk_ctx* dpdk_cfgs,
                     const struct pcap_ctx* pcap_cfgs,
                     unsigned int pcap_num)
{
    struct thread_ctx* ctx = NULL;
    sem_t sem, sem_stop;
    unsigned int i;
    int ret;

    log_info("Starting threads...");

    log_set_lock(log_lock_function, &log_mutex);

    /* init semaphore for synchronous threads startup */
    if (sem_init(&sem, 0, 0)) {
        log_error("sem_init failed: %s", strerror(errno));
        return (errno);
    }

    if (sem_init(&sem_stop, 0, 0)) {
        log_error("sem_init failed: %s", strerror(errno));
        return (errno);
    }

    /* create threads contexts */
    ctx = malloc(sizeof(*ctx) * (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus));
    if (!ctx)
        return (ENOMEM);
    bzero(ctx, sizeof(*ctx) * (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus));
    for (i = 0; i < cpus->nb_needed_pcap_cpus; i++) {
        ctx[i].sem = &sem;
        ctx[i].sem_stop = &sem_stop;
        ctx[i].rx_port_id = -1;
        ctx[i].tx_port_id = 0;
        ctx[i].nbruns = opts->nbruns;
        ctx[i].pcap_cache = &(dpdk_cfgs[i].pcap_caches[0]);
        ctx[i].nb_pkt = pcap_cfgs[i].nb_pkts;
        ctx[i].nb_tx_queues = pcap_cfgs[i].tx_queues;
        ctx[i].nb_tx_queues_start = i * pcap_cfgs[i].tx_queues;
        ctx[i].nb_tx_queues_end = ctx[i].nb_tx_queues_start - 1 + pcap_cfgs[i].tx_queues;
        ctx[i].slow_mode = opts->slow_mode;
        ctx[i].timeout = opts->timeout;
        ctx[i].thread_id = i;
        ctx[i].t_type = PCAP_THREAD;
        if (opts->max_mpps == -1 && opts->max_mbps == -1) {
            ctx[i].tx_rate_cycles = -1;
        } else if (opts->max_mpps > 0) {
            ctx[i].tx_rate_cycles = get_tx_cycles_mpps(opts);
        } else {
            ctx[i].tx_rate_cycles = get_tx_cycles_mbps(&pcap_cfgs[i], opts);
        }
    }

    int rx_queues_per_core = opts->nb_rx_queues / opts->nb_rx_cores;
    int rx_remainder_queues = opts->nb_rx_queues % opts->nb_rx_cores;

    log_trace("Setting contex for recv threads");
    /* Here I set the context for the recv thread */
    for (int j = 0, i = cpus->nb_needed_pcap_cpus; i < cpus->nb_needed_pcap_cpus + cpus->nb_needed_recv_cpus; i++, j++) {
        ctx[i].sem = &sem;
        ctx[i].sem_stop = &sem_stop;
        ctx[i].rx_port_id = (i - cpus->nb_needed_pcap_cpus) / cpus->nb_needed_recv_cpus;
        ctx[i].tx_port_id = -1;
        ctx[i].nbruns = opts->nbruns;
        ctx[i].pcap_cache = &(dpdk_cfgs[0].pcap_caches[0]);
        ctx[i].tx_rate_cycles = -1;
        ctx[i].nb_pkt = pcap_cfgs[0].nb_pkts;
        ctx[i].nb_tx_queues = 0;
        ctx[i].slow_mode = opts->slow_mode;
        ctx[i].timeout = opts->timeout;
        ctx[i].thread_id = i;
        ctx[i].t_type = RECV_THREAD;
        ctx[i].nb_rx_queues = opts->nb_rx_queues;
        // ctx[i].nb_rx_queues_start = j * (opts->nb_rx_queues / opts->nb_rx_cores);
        // ctx[i].nb_rx_queues_end = ctx[i].nb_rx_queues_start - 1 + (opts->nb_rx_queues / opts->nb_rx_cores);
        // Assign an extra queue to the first `remainder_queues` cores
        int assigned_queues = rx_queues_per_core + (j < rx_remainder_queues ? 1 : 0);
        ctx[i].nb_rx_queues_start = (j * rx_queues_per_core) + (j < rx_remainder_queues ? j : rx_remainder_queues);
        ctx[i].nb_rx_queues_end = ctx[i].nb_rx_queues_start + assigned_queues - 1;
    }

    log_trace("Setting context for stats threads");
    /* Here I set the context for the stats threads */
    for (i = cpus->nb_needed_pcap_cpus + cpus->nb_needed_recv_cpus; i < cpus->nb_needed_pcap_cpus + cpus->nb_needed_recv_cpus + cpus->nb_needed_stats_cpus; i++) {
        ctx[i].sem = &sem;
        ctx[i].sem_stop = &sem_stop;
        ctx[i].rx_port_id = i - cpus->nb_needed_pcap_cpus - cpus->nb_needed_recv_cpus;
        ctx[i].tx_port_id = -1;
        ctx[i].nbruns = opts->nbruns;
        ctx[i].pcap_cache = &(dpdk_cfgs[0].pcap_caches[0]);
        ctx[i].tx_rate_cycles = -1;
        ctx[i].nb_pkt = pcap_cfgs[0].nb_pkts;
        ctx[i].nb_tx_queues = 0;
        ctx[i].slow_mode = opts->slow_mode;
        ctx[i].timeout = opts->timeout;
        ctx[i].thread_id = i;
        ctx[i].t_type = STATS_THREAD;

        int port_no = i - cpus->nb_needed_pcap_cpus - cpus->nb_needed_recv_cpus;
        /* Initialize CSV files if the corresponding flag is set */
        if (opts->write_csv) {
            char file_name[PATH_MAX];
            if (opts->nb_stats_file_name > 0) {
                log_trace("Using custom stats file name for port %u: %s", port_no, opts->stats_name[port_no]);
                strncpy(file_name, opts->stats_name[port_no], PATH_MAX);
            } else {
                snprintf(file_name, PATH_MAX, "results_port_%u.csv", port_no);
            }
            log_trace("Opening CSV file for thread %u: %s", i, file_name);
            FILE *ptr = fopen(file_name, "w");

            if (ptr == NULL) {
                log_error("open file failed: %s", file_name);
                free(ctx);
                return -1;
            }
            ctx[i].csv_ptr = ptr;
        }
    }

    /* launch threads, which will wait on the semaphore to start */
    for (i = 0; i < (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus); i++) {
        log_info("[Thread %u] Start on core %u", i, cpus->cpus_to_use[i + 1]);
        ret = rte_eal_remote_launch(remote_thread, &(ctx[i]),
                                    cpus->cpus_to_use[i + 1]); /* skip fake master core */
        if (ret) {
            log_error("rte_eal_remote_launch failed: %s", strerror(ret));
            free(ctx);
            return (ret);
        }
    }

    if (opts->wait) {
        /* wait for ENTER and starts threads */
        log_info("Threads are ready to be launched, please press ENTER to start sending packets.");
        for (ret = getchar(); ret != '\n'; ret = getchar()) ;
    } else {
        /*
          wait 1sec to be sure that threads are spawned and ready to start
          simultaneously (for stats concerns)
        */
        sleep (1);
    }

    log_info("Starting threads, 5 seconds to prepare...");
    sleep(5); // Wait for threads to be ready

    for (i = 0; i < (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus); i++) {
        ret = sem_post(&sem);
        if (ret) {
            log_error("sem_post failed: %s", strerror(errno));
            free(ctx);
            return (errno);
        }
    }

    log_info("Timeout value is: %d", opts->timeout);
    if (opts->timeout > 0) {
        sleep(opts->timeout);

        for (i = 0; i < (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus); i++) {
            ret = sem_post(&sem_stop);
            if (ret) {
                log_error("sem_post failed: %s", strerror(errno));
                free(ctx);
                return (errno);
            }
        }
    }

    /* wait all threads */
    rte_eal_mp_wait_lcore();

    for (i = 0; i < (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus); i++) {
        if (opts->write_csv && ctx[i].csv_ptr != NULL) {
            log_info("Closing CSV file for thread %u", i);
            fclose(ctx[i].csv_ptr);
            ctx[i].csv_ptr = NULL;
        }
    }

    /* get results */
    ret = process_result_stats(cpus, dpdk_cfgs, opts, ctx);
    log_info("Finished processing results.");
    log_debug("Freeing threads context.");
    free(ctx);

    pthread_mutex_destroy(&log_mutex);
    sem_destroy(&sem);
    sem_destroy(&sem_stop);
    return (ret);
}