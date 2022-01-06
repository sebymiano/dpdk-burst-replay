/*
  SPDX-License-Identifier: BSD-3-Clause
  Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.
*/

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

/* DPDK includes */
#include <rte_version.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_errno.h>

#include "main.h"

static struct rte_eth_conf ethconf = {
#ifdef RTE_VER_YEAR
    /* version  > to 2.2.0, last one with old major.minor.patch system */
    .link_speeds = ETH_LINK_SPEED_AUTONEG,
#else
    /* compatibility with older version */
    .link_speed = 0,        // autonegociated speed link
    .link_duplex = 0,       // autonegociated link mode
#endif
    .rxmode = {
        .mq_mode = ETH_MQ_RX_NONE,
    },

    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,  // Multi queue packet routing mode.
    },

    .fdir_conf = {
        .mode = RTE_FDIR_MODE_NONE, // Disable flow director support
    },

    .intr_conf = {
        .lsc = 0,                   // Disable lsc interrupts
    },
};

static struct rte_eth_conf rx_port_conf = {
	.rxmode = {
		.mq_mode	= ETH_MQ_RX_RSS,
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.offloads = DEV_RX_OFFLOAD_CHECKSUM,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP | ETH_RSS_UDP |
				ETH_RSS_TCP | ETH_RSS_SCTP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
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
    snprintf(buf_coremask, 20, "0x%lx", cpus->coremask);
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
    for (i = 0; opts->pcicards[i]; i++) {
        eal_args = myrealloc(eal_args, sizeof(char*) * (cpt + 2));
        if (!eal_args)
            return (NULL);
        // eal_args[cpt - 1] = "--pci-whitelist"; /* overwrite "NULL" */
        eal_args[cpt - 1] = "--allow"; /* overwrite "NULL" */
        eal_args[cpt] = opts->pcicards[i];
        eal_args[cpt + 1] = NULL;
        cpt += 2;
    }

    if (opts->nb_stats > 0) {
        // If we setup a device to read packets from
        for (i = 0; opts->stats[i]; i++) {
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

int dpdk_init_port(const struct cpus_bindings* cpus, int port)
{
    int                 ret, i;
#ifdef DEBUG
    struct rte_eth_link eth_link;
#endif /* DEBUG */

    if (!cpus)
        return (EINVAL);

    ret = rte_eth_promiscuous_enable(port);

    if (ret) {
        fprintf(stderr, "DPDK: Failed to enable promiscous mode on port: %d\n", port);
        return (-1);
    }

    /* Configure for each port (ethernet device), the number of rx queues & tx queues */
    if (rte_eth_dev_configure(port,
                              0, /* nb rx queue */
                              NB_TX_QUEUES, /* nb tx queue */
                              &ethconf) < 0) {
        fprintf(stderr, "DPDK: RTE ETH Ethernet device configuration failed\n");
        return (-1);
    }

    /* Then allocate and set up the transmit queues for this Ethernet device  */
    for (i = 0; i < NB_TX_QUEUES; i++) {
        ret = rte_eth_tx_queue_setup(port,
                                     i,
                                     TX_QUEUE_SIZE,
                                     cpus->numacore,
                                     &txconf);
        if (ret < 0) {
            fprintf(stderr, "DPDK: RTE ETH Ethernet device tx queue %i setup failed: %s",
                    i, strerror(-ret));
            return (ret);
        }
    }

    /* Start the ethernet device */
    if (rte_eth_dev_start(port) < 0) {
        fprintf(stderr, "DPDK: RTE ETH Ethernet device start failed\n");
        return (-1);
    }

#ifdef DEBUG
    /* Get link status and display it. */
    rte_eth_link_get(port, &eth_link);
    if (eth_link.link_status) {
        printf(" Link up - speed %u Mbps - %s\n",
               eth_link.link_speed,
               (eth_link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
               "full-duplex" : "half-duplex\n");
    } else {
        printf("Link down\n");
    }
#endif /* DEBUG */
    return (0);
}

static struct rte_mempool *
dpdk_mbuf_pool_create(const char *type, uint8_t pid, uint8_t queue_id,
			uint32_t nb_mbufs, int socket_id, int cache_size){
	struct rte_mempool *mp;
	char name[RTE_MEMZONE_NAMESIZE];
	uint64_t sz;

	snprintf(name, sizeof(name), "%-12s%u:%u", type, pid, queue_id);

	sz = nb_mbufs * (DEFAULT_MBUF_SIZE + sizeof(struct rte_mbuf));
	sz = RTE_ALIGN_CEIL(sz + sizeof(struct rte_mempool), 1024);

	/* create the mbuf pool */
	mp = rte_pktmbuf_pool_create(name, nb_mbufs, cache_size, 0, DEFAULT_MBUF_SIZE, socket_id);
	if (mp == NULL)
		fprintf(stderr,
			"Cannot create mbuf pool (%s) port %d, queue %d, nb_mbufs %d, socket_id %d: %s",
			name, pid, queue_id, nb_mbufs, socket_id, rte_strerror(rte_errno));

	return mp;
}

int dpdk_init_read_port(struct cpus_bindings* cpus, int port)
{
    int                 ret, i;
    struct rte_eth_dev_info dev_info;     /**< PCI info + driver name */
    struct rte_eth_conf local_port_conf = rx_port_conf;
#ifdef DEBUG
    struct rte_eth_link eth_link;
#endif /* DEBUG */

    if (!cpus)
        return (EINVAL);

    ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
            "Error during getting device (port %u) info: %s\n",
            port, strerror(-ret));

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
        dev_info.flow_type_rss_offloads;
    if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
            rx_port_conf.rx_adv_conf.rss_conf.rss_hf) {
        printf("Port %u modified RSS hash function based on hardware support,"
            "requested:%#"PRIx64" configured:%#"PRIx64"\n",
            port,
            rx_port_conf.rx_adv_conf.rss_conf.rss_hf,
            local_port_conf.rx_adv_conf.rss_conf.rss_hf);
    }

    /* Configure for each port (ethernet device), the number of rx queues & tx queues */
    if (rte_eth_dev_configure(port,
                              NB_RX_QUEUES, /* nb rx queue */
                              0, /* nb tx queue */
                              &local_port_conf) < 0) {
        fprintf(stderr, "DPDK: RTE ETH Ethernet device configuration failed\n");
        return (-1);
    }

    uint16_t nb_txd = 0;
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);

    if (ret < 0) {
        fprintf(stderr, "rte_eth_dev_adjust_nb_rx_tx_desc: err=%d, port=%d\n", ret, port);
        return (-1);
    }

    if (cpus->pktmbuf_pool == NULL) {
        cpus->pktmbuf_pool = rte_pktmbuf_pool_create("Default RX", 8192,
					MEMPOOL_CACHE_SIZE, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE,
					cpus->numacore);
    }

    if (cpus->pktmbuf_pool == NULL) {
        fprintf(stderr, "Cannot init mbuf pool (port %u)\n", port);
        return (-1);
    } else {
        printf("Allocated mbuf pool on socket %d\n", cpus->numacore);
    }

    /* Then allocate and set up the transmit queues for this Ethernet device  */
    for (int q = 0; q < NB_RX_QUEUES; q++) {
        struct rte_eth_rxconf rxq_conf;

        ret = rte_eth_dev_info_get(port, &dev_info);
        if (ret != 0) {
            fprintf(stderr, "Error during getting device (port %u) info: %s\n", port, strerror(-ret));
            return (-1);
        }

        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = rx_port_conf.rxmode.offloads;

        ret = rte_eth_rx_queue_setup(port, q, nb_rxd, cpus->numacore,
						             &rxq_conf, cpus->pktmbuf_pool);

        if (ret < 0) {
            fprintf(stderr, "DPDK: RTE ETH Ethernet device RX queue %i setup failed: %s",
                    i, strerror(-ret));
            return (ret);
        }
    }

    /* Start the ethernet device */
    if (rte_eth_dev_start(port) < 0) {
        fprintf(stderr, "DPDK: RTE ETH Ethernet device start failed\n");
        return (-1);
    }

    ret = rte_eth_promiscuous_enable(port);
    if (ret) {
        fprintf(stderr, "DPDK: Failed to enable promiscous mode on port: %d\n", port);
        return (-1);
    }

#ifdef DEBUG
    /* Get link status and display it. */
    rte_eth_link_get(port, &eth_link);
    if (eth_link.link_status) {
        printf(" Link up - speed %u Mbps - %s\n",
               eth_link.link_speed,
               (eth_link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
               "full-duplex" : "half-duplex\n");
    } else {
        printf("Link down\n");
    }
#endif /* DEBUG */
    return (0);
}

int init_dpdk_eal_mempool(const struct cmd_opts* opts,
                          const struct cpus_bindings* cpus,
                          struct dpdk_ctx* dpdk)
{
    char**          eal_args;
    int             eal_args_ac = 0;
    unsigned int    nb_ports;
    int             ret;

    if (!opts || !cpus || !dpdk)
        return (EINVAL);

    /* API BREAKAGE ON 17.05 */
#if API_OLDEST_THAN(17, 05)
    rte_set_log_level(RTE_LOG_ERR);
#else /* if DPDK >= 17.05 */
    rte_log_set_global_level(RTE_LOG_ERR);
#endif

    /* craft an eal arg list */
    eal_args = fill_eal_args(opts, cpus, dpdk, &eal_args_ac);
    if (!eal_args) {
        printf("%s: fill_eal_args failed.\n", __FUNCTION__);
        return (1);
    }

#ifdef DEBUG
    puts("EAL ARGS:");
    for (int i = 0; eal_args[i]; i++)
        printf("eal_args[%i] = %s\n", i, eal_args[i]);
#endif /* DEBUG */

    /* DPDK RTE EAL INIT */
    ret = rte_eal_init(eal_args_ac, eal_args);
    free(eal_args);
    if (ret < 0) {
        printf("%s: rte_eal_init failed (%d)\n", __FUNCTION__, ret);
        return (ret);
    }

    /* check that dpdk see enough usable cores */
    if (rte_lcore_count() != cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus + 1) {
        printf("%s error: not enough rte_lcore founds\n", __FUNCTION__);
        printf("Required: %d, obtained: %d\n", cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus + 1, rte_lcore_count());
        return (1);
    }

    /* check that dpdk detects all wanted/needed NIC ports */
#if API_OLDEST_THAN(18, 05) /* API BREAKAGE ON 18.05 */
    nb_ports = rte_eth_dev_count();
#else /* if DPDK >= 18.05 */
    nb_ports = rte_eth_dev_count_avail();
#endif
    if (nb_ports != opts->nb_total_ports) {
        printf("%s error: wanted %u NIC ports, found %u\n", __FUNCTION__,
               opts->nb_total_ports, nb_ports);
        return (1);
    }

    printf("-> Create mempool of %lu mbufs of %lu octs.\n",
           dpdk->nb_mbuf, dpdk->mbuf_sz);
    dpdk->pktmbuf_pool = rte_mempool_create("dpdk_replay_mempool",
                                            dpdk->nb_mbuf,
                                            dpdk->mbuf_sz,
                                            MBUF_CACHE_SZ,
                                            sizeof(struct rte_pktmbuf_pool_private),
                                            rte_pktmbuf_pool_init, NULL,
                                            rte_pktmbuf_init, NULL,
                                            cpus->numacore,
                                            0);
    if (dpdk->pktmbuf_pool == NULL) {
        fprintf(stderr, "DPDK: RTE Mempool creation failed (%s)\n",
                rte_strerror(rte_errno));
#if API_AT_LEAST_AS_RECENT_AS(18, 05)
        if (rte_errno == ENOMEM
            && (dpdk->nb_mbuf * dpdk->mbuf_sz /1024/1024) > RTE_MAX_MEM_MB_PER_LIST)
            fprintf(stderr, "Your version of DPDK was configured to use at maximum"
                    " %u Mo, or you try to allocate ~%lu Mo.\n"
                    "Try to recompile DPDK by setting CONFIG_RTE_MAX_MEM_MB_PER_LIST"
                    " according to your needs.\n", RTE_MAX_MEM_MB_PER_LIST,
                    dpdk->nb_mbuf * dpdk->mbuf_sz /1024/1024);
#endif /* API_AT_LEAST_AS_RECENT_AS(18, 05) */
        return (rte_errno);
    }
    return (0);
}

int init_dpdk_ports(struct cpus_bindings* cpus, const struct cmd_opts* opts)
{
    int i;
    int numa;

    if (!cpus)
        return (EINVAL);

    for (i = 0; (unsigned)i < cpus->nb_needed_pcap_cpus; i++) {
        /* if the port ID isn't on the good numacore, exit */
        numa = rte_eth_dev_socket_id(i);
        if (numa != cpus->numacore) {
            fprintf(stderr, "port %i is not on the good numa id (%i).\n", i, numa);
            return (1);
        }
        /* init ports */
        if (dpdk_init_port(cpus, i))
            return (1);
        printf("-> NIC port %i ready.\n", i);
    }

    // Now if I have a device to read packets from I need to setup the corresponding port
    for (i = cpus->nb_needed_pcap_cpus; (unsigned)i < (opts->nb_total_ports); i++) {
        /* if the port ID isn't on the good numacore, exit */
        numa = rte_eth_dev_socket_id(i);
        if (numa != cpus->numacore) {
            fprintf(stderr, "port %i is not on the good numa id (%i).\n", i, numa);
            return (1);
        }
        /* init ports */
        if (dpdk_init_read_port(cpus, i))
            return (1);
        printf("-> NIC port %i (for read) ready.\n", i);
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

int remote_thread(void* thread_ctx)
{
    struct thread_ctx*  ctx;
    struct rte_mbuf**   mbuf;
    struct timespec     start, end;
    unsigned int        tx_queue;
    int                 ret, thread_id, index, i, run_cpt, retry_tx;
    int                 nb_sent, to_sent, total_to_sent, total_sent;
    int                 nb_drop;
    bool                is_stats_thread = false;
    int        sem_value;

    if (!thread_ctx)
        return (EINVAL);

    /* retrieve thread context */
    ctx = (struct thread_ctx*)thread_ctx;

    /* init semaphore to wait to start the burst */
    ret = sem_wait(ctx->sem);
    if (ret) {
        fprintf(stderr, "sem_wait failed on thread %i: %s\n",
                thread_id, strerror(ret));
        return (ret);
    }

    /* get the start time */
    ret = clock_gettime(CLOCK_MONOTONIC, &start);
    if (ret) {
        fprintf(stderr, "clock_gettime failed on start for thread %i: %s\n",
                thread_id, strerror(errno));
        return (errno);
    }

    printf("RX port id: %d, TX port id: %d\n", ctx->rx_port_id, ctx->tx_port_id);
    if (ctx->rx_port_id >= 0) {
        is_stats_thread = true;
        thread_id = ctx->rx_port_id;
    } else {
        is_stats_thread = false;
        thread_id = ctx->tx_port_id;
    }

    #ifdef DEBUG
    printf("Starting thread %i.\n", thread_id);
    #endif

    if (!is_stats_thread) {
        printf("Sending PCAP trace. Wait %d seconds\n", ctx->timeout);
        mbuf = ctx->pcap_cache->mbufs;

        /* iterate on each wanted runs */
        for (run_cpt = ctx->nbruns, tx_queue = ctx->total_drop = ctx->total_drop_sz = 0;
            run_cpt;
            ctx->total_drop += nb_drop, run_cpt--) {
            /* iterate on pkts for every batch of BURST_SZ number of packets */
            for (total_to_sent = ctx->nb_pkt, nb_drop = 0, to_sent = min(BURST_SZ, total_to_sent);
                to_sent;
                total_to_sent -= to_sent, to_sent = min(BURST_SZ, total_to_sent)) {
                /* calculate the mbuf index for the current batch */
                index = ctx->nb_pkt - total_to_sent;

                /* send the burst batch, and retry NB_RETRY_TX times if we */
                /* didn't success to sent all the wanted batch */
                for (total_sent = 0, retry_tx = NB_RETRY_TX;
                    total_sent < to_sent && retry_tx;
                    total_sent += nb_sent, retry_tx--) {
                    nb_sent = rte_eth_tx_burst(ctx->tx_port_id,
                                            (tx_queue++ % NB_TX_QUEUES),
                                            &(mbuf[index + total_sent]),
                                            to_sent - total_sent);
                    if (retry_tx != NB_RETRY_TX &&
                        tx_queue % NB_TX_QUEUES == 0)
                        usleep(100);
                }
                /* free unseccessfully sent  */
                if (unlikely(!retry_tx))
                    for (i = total_sent; i < to_sent; i++) {
                        nb_drop++;
                        ctx->total_drop_sz += mbuf[index + i]->pkt_len;
                        rte_pktmbuf_free(mbuf[index + i]);
                    }
            }
    #ifdef DEBUG
            if (unlikely(nb_drop))
                printf("[thread %i]: on loop %i: sent %i pkts (%i were dropped).\n",
                    thread_id, ctx->nbruns - run_cpt, ctx->nb_pkt, nb_drop);
    #endif /* DEBUG */


            sem_getvalue(ctx->sem_stop, &sem_value);
            if (sem_value > 0) {
                break;
            }

            if (ctx->slow_mode) {
                // TODO: Better control of sending rate in the future
                sleep(1);
                // Sleep for 1.5 seconds
                // usleep(1.5*1000000);
            }
        }
    } else if (is_stats_thread && ctx->t_type == STATS_THREAD) {
        struct rte_eth_stats  old_stats;
        struct rte_eth_stats  stats;

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
                printf("Error while reading stats from port: %u\n", ctx->rx_port_id);
                sleep(1);
                continue;
            }

            printf("-> Stats for port: %u\n\n", ctx->rx_port_id);
            if (ctx->csv_ptr) {
                fprintf(ctx->csv_ptr, "%u,%u,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n", 
                                      ctx->rx_port_id, run_cpt,
                                      stats.ipackets - old_stats.ipackets,
                                      stats.ibytes - old_stats.ibytes,
                                      stats.opackets - old_stats.opackets,
                                      stats.obytes - old_stats.obytes);
            }
            printf("  RX-packets: %-10"PRIu64"  RX-bytes:  %-10"PRIu64"\n", 
                    stats.ipackets - old_stats.ipackets,
                    stats.ibytes - old_stats.ibytes);
            printf("  RX-nombuf:  %-10"PRIu64"\n", stats.rx_nombuf - old_stats.rx_nombuf);
            printf("  Errors:  %-10"PRIu64"\n", stats.ierrors - old_stats.ierrors);
            printf("  Missed:  %-10"PRIu64"\n", stats.imissed - old_stats.imissed);
            printf("  TX-packets: %-10"PRIu64"  TX-bytes:  %-10"PRIu64"\n", 
                    stats.opackets - old_stats.opackets, 
                    stats.obytes - old_stats.obytes);
            printf("\n");

            memcpy(&old_stats, &stats, sizeof(stats));
            sleep(1);
            
            sem_getvalue(ctx->sem_stop, &sem_value);
            if (sem_value > 0) {
                break;
            }
        }
    } else {
        // We are in the receive thread
        uint16_t nb_rx;
        for (;;) {
            struct rte_mbuf *bufs[BURST_SIZE];
            for (int q = 0; q < NB_RX_QUEUES; q++) {
                nb_rx = rte_eth_rx_burst(ctx->rx_port_id, q, bufs, BURST_SIZE);
                if (unlikely(nb_rx == 0))
                    continue;

                rte_pktmbuf_free_bulk(bufs, nb_rx);
            }

            sem_getvalue(ctx->sem_stop, &sem_value);
            if (sem_value > 0) {
                break;
            }
        }
    }

    /* get the ends time and calculate the duration */
    ret = clock_gettime(CLOCK_MONOTONIC, &end);
    if (ret) {
        fprintf(stderr, "clock_gettime failed on finish for thread %i: %s\n",
                thread_id, strerror(errno));
        return (errno);
    }
    ctx->duration = timespec_diff_to_double(start, end);
#ifdef DEBUG
    printf("Exiting thread %i properly.\n", thread_id);
#endif /* DEBUG */
    return (0);
}

int process_result_stats(const struct cpus_bindings* cpus,
                         const struct dpdk_ctx* dpdk,
                         const struct cmd_opts* opts,
                         const struct thread_ctx* ctx)
{
    double              pps, bitrate;
    double              total_pps, total_bitrate;
    unsigned long int   total_pkt_sent, total_pkt_sent_sz;
    unsigned int        i, total_drop, total_pkt;

    if (!cpus || !dpdk || !opts || !ctx)
        return (EINVAL);

    total_pps = total_bitrate = 0;
    total_drop = 0;
    puts("RESULTS :");
    for (i = 0; i < cpus->nb_needed_pcap_cpus; i++) {
        total_pkt_sent = (ctx[i].nb_pkt * opts->nbruns) - ctx[i].total_drop;
        total_pkt_sent_sz = (dpdk->pcap_sz * opts->nbruns) - ctx[i].total_drop_sz;
        pps = total_pkt_sent / ctx[i].duration;
        bitrate = total_pkt_sent_sz / ctx[i].duration
            * 8 /* Bytes to bits */
            / 1024 /* bits to Kbits */
            / 1024 /* Kbits to Mbits */
            / 1024; /* Mbits to Gbits */
        total_bitrate += bitrate;
        total_pps += pps;
        total_drop += ctx[i].total_drop;
        printf("[thread %02u]: %f Gbit/s, %f pps on %f sec (%u pkts dropped)\n",
               i, bitrate, pps, ctx[i].duration, ctx[i].total_drop);
    }
    puts("-----");
    printf("TOTAL        : %.3f Gbit/s. %.3f pps.\n", total_bitrate, total_pps);
    total_pkt = ctx[0].nb_pkt * opts->nbruns * cpus->nb_needed_pcap_cpus;
    printf("Total dropped: %u/%u packets (%f%%)\n", total_drop, total_pkt,
           (double)(total_drop * 100) / (double)(total_pkt));
    return (0);
}

int start_all_threads(const struct cmd_opts* opts,
                     const struct cpus_bindings* cpus,
                     const struct dpdk_ctx* dpdk,
                     const struct pcap_ctx* pcap)
{
    struct thread_ctx* ctx = NULL;
    sem_t sem, sem_stop;
    unsigned int i;
    int ret;

    /* init semaphore for synchronous threads startup */
    if (sem_init(&sem, 0, 0)) {
        fprintf(stderr, "sem_init failed: %s\n", strerror(errno));
        return (errno);
    }

    if (sem_init(&sem_stop, 0, 0)) {
        fprintf(stderr, "sem_init failed: %s\n", strerror(errno));
        return (errno);
    }

    /* create threads contexts */
    ctx = malloc(sizeof(*ctx) * (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus));
    if (!ctx)
        return (ENOMEM);
    bzero(ctx, sizeof(*ctx) * (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus));
    for (i = 0; i < cpus->nb_needed_pcap_cpus; i++) {
        ctx[i].sem = &sem;
        ctx[i].sem_stop = &sem_stop;
        ctx[i].rx_port_id = -1;
        ctx[i].tx_port_id = i;
        ctx[i].nbruns = opts->nbruns;
        ctx[i].pcap_cache = &(dpdk->pcap_caches[i]);
        ctx[i].nb_pkt = pcap->nb_pkts;
        ctx[i].nb_tx_queues = NB_TX_QUEUES;
        ctx[i].slow_mode = opts->slow_mode;
        ctx[i].timeout = opts->timeout;
        ctx[i].t_type = PCAP_THREAD;
    }

    /* Here I set the context for the recv thread */
    for (i = cpus->nb_needed_pcap_cpus; i < cpus->nb_needed_pcap_cpus + cpus->nb_needed_recv_cpus; i++) {
        ctx[i].sem = &sem;
        ctx[i].sem_stop = &sem_stop;
        ctx[i].rx_port_id = i - cpus->nb_needed_pcap_cpus;
        ctx[i].tx_port_id = -1;
        ctx[i].nbruns = opts->nbruns;
        ctx[i].pcap_cache = &(dpdk->pcap_caches[i]);
        ctx[i].nb_pkt = pcap->nb_pkts;
        ctx[i].nb_tx_queues = NB_TX_QUEUES;
        ctx[i].slow_mode = opts->slow_mode;
        ctx[i].timeout = opts->timeout;
        ctx[i].t_type = RECV_THREAD;
    }

    /* Here I set the context for the stats threads */
    for (i = cpus->nb_needed_pcap_cpus + cpus->nb_needed_recv_cpus; i < cpus->nb_needed_pcap_cpus + cpus->nb_needed_recv_cpus + cpus->nb_needed_stats_cpus; i++) {
        ctx[i].sem = &sem;
        ctx[i].sem_stop = &sem_stop;
        ctx[i].rx_port_id = i - cpus->nb_needed_pcap_cpus - cpus->nb_needed_recv_cpus;
        ctx[i].tx_port_id = -1;
        ctx[i].nbruns = opts->nbruns;
        ctx[i].pcap_cache = &(dpdk->pcap_caches[i]);
        ctx[i].nb_pkt = pcap->nb_pkts;
        ctx[i].nb_tx_queues = NB_TX_QUEUES;
        ctx[i].slow_mode = opts->slow_mode;
        ctx[i].timeout = opts->timeout;
        ctx[i].t_type = STATS_THREAD;

        int port_no = i - cpus->nb_needed_pcap_cpus - cpus->nb_needed_recv_cpus;
        /* Initialize CSV files if the corresponding flag is set */
        if (opts->write_csv) {
            char file_name[30];
            if (opts->nb_stats_file_name > 0) {
                strncpy(file_name, opts->stats_name[port_no], 30);
            } else {
                snprintf(file_name, 30, "results_port_%u.csv", port_no);
            }

            FILE *ptr = fopen(file_name, "w");

            if (ptr == NULL) {
                fprintf(stderr, "open file failed: %s\n", file_name);
                free(ctx);
                return -1;
            }
            ctx[i].csv_ptr = ptr;
        }
    }

    /* launch threads, which will wait on the semaphore to start */
    for (i = 0; i < (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus); i++) {
        printf("Start thread: %u on core %u\n", i, cpus->cpus_to_use[i + 1]);
        ret = rte_eal_remote_launch(remote_thread, &(ctx[i]),
                                    cpus->cpus_to_use[i + 1]); /* skip fake master core */
        if (ret) {
            fprintf(stderr, "rte_eal_remote_launch failed: %s\n", strerror(ret));
            free(ctx);
            return (ret);
        }
    }

    if (opts->wait) {
        /* wait for ENTER and starts threads */
        puts("Threads are ready to be launched, please press ENTER to start sending packets.");
        for (ret = getchar(); ret != '\n'; ret = getchar()) ;
    } else {
        /*
          wait 1sec to be sure that threads are spawned and ready to start
          simultaneously (for stats concerns)
        */
        sleep (1);
    }

    for (i = 0; i < (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus); i++) {
        ret = sem_post(&sem);
        if (ret) {
            fprintf(stderr, "sem_post failed: %s\n", strerror(errno));
            free(ctx);
            return (errno);
        }
    }

    printf("Timeout value is: %d\n", opts->timeout);
    if (opts->timeout > 0) {
        sleep(opts->timeout);

        for (i = 0; i < (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus); i++) {
            ret = sem_post(&sem_stop);
            if (ret) {
                fprintf(stderr, "sem_post failed: %s\n", strerror(errno));
                free(ctx);
                return (errno);
            }
        }
    }

    /* wait all threads */
    rte_eal_mp_wait_lcore();

    for (i = 0; i < (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus); i++) {
        if (opts->write_csv && ctx[i].csv_ptr != NULL) {
            fclose(ctx[i].csv_ptr);
        }
    }

    /* get results */
    ret = process_result_stats(cpus, dpdk, opts, ctx);
    free(ctx);
    return (ret);
}

void dpdk_cleanup(struct dpdk_ctx* dpdk, struct cpus_bindings* cpus)
{
    unsigned int i;

    /* free caches */
    if (dpdk->pcap_caches) {
        for (i = 0; i < cpus->nb_needed_pcap_cpus; i++)
            free(dpdk->pcap_caches[i].mbufs);
        free(dpdk->pcap_caches);
    }

    /* close ethernet devices */
    for (i = 0; i < cpus->nb_needed_pcap_cpus; i++)
        rte_eth_dev_close(i);

    /* free mempool */
    if (dpdk->pktmbuf_pool)
        rte_mempool_free(dpdk->pktmbuf_pool);
    return ;
}
