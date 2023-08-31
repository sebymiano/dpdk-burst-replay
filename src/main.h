/*
  SPDX-License-Identifier: BSD-3-Clause
  Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.
*/

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include <semaphore.h>
#include <stdbool.h>

#include "config_yaml.h"

#define DEBUG           1
#define MBUF_CACHE_SZ   32
#define TX_QUEUE_SIZE   4096
#define RX_QUEUE_SIZE   4096
#define NB_TX_QUEUES    4 /* ^2 needed to make fast modulos % */
#define NB_RX_QUEUES    1 /* ^2 needed to make fast modulos % */
#define NB_MAX_PORTS    5
#define BURST_SZ        128
#define NB_RETRY_TX     (NB_TX_QUEUES * 2)
#define MEMPOOL_CACHE_SIZE 256
#define BURST_SIZE 32

#define RTE_TEST_RX_DESC_DEFAULT 1024

#define PG_JUMBO_FRAME_LEN (9600 + RTE_ETHER_CRC_LEN + RTE_ETHER_HDR_LEN)
#define PG_ETHER_MAX_JUMBO_FRAME_LEN   PG_JUMBO_FRAME_LEN
#define DEFAULT_MBUF_SIZE	(PG_ETHER_MAX_JUMBO_FRAME_LEN + RTE_PKTMBUF_HEADROOM)

#define TX_PTHRESH 36 // Default value of TX prefetch threshold register.
#define TX_HTHRESH 0  // Default value of TX host threshold register.
#define TX_WTHRESH 0  // Default value of TX write-back threshold register.

#ifndef min
#define min(x, y) (x < y ? x : y)
#endif /* min */
#ifndef max
#define max(x, y) (x > y ? x : y)
#endif /* max */

#define API_OLDEST_THAN(year, month)                     \
    ((defined RTE_VER_YEAR && RTE_VER_YEAR == year       \
      && defined RTE_VER_MONTH && RTE_VER_MONTH < month) \
     || defined RTE_VER_YEAR && RTE_VER_YEAR < year)

#define API_AT_LEAST_AS_RECENT_AS(year, month)            \
    ((defined RTE_VER_YEAR && RTE_VER_YEAR == year        \
      && defined RTE_VER_MONTH && RTE_VER_MONTH >= month) \
     || defined RTE_VER_YEAR && RTE_VER_YEAR >= year)

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;

/* struct to store the command line args */
struct cmd_opts {
    char**          pcicards;
    int             nb_pcicards;
    int             numacore;
    int             nbruns;
    int             timeout;
    int           max_mpps;
    int             wait;
    int             write_csv;
    int             slow_mode;
    trace_t*        traces;
    int             nb_traces;
    char**          stats;
    int             nb_stats;
    int             nb_total_ports;
    int             nb_stats_file_name;
    char**          stats_name;
    char*           config_file;
};

/* struct to store the cpus context */
struct                  cpus_bindings {
    int                 numacores; /* nb of numacores of the system */
    int                 numacore; /* wanted numacore to run */
    unsigned int        nb_available_cpus;
    unsigned int        nb_needed_pcap_cpus;
    unsigned int        nb_needed_stats_cpus;
    unsigned int        nb_needed_recv_cpus;
    unsigned int*       cpus_to_use;
    char*               prefix;
    char*               suffix;
    uint64_t            coremask;
    struct q_info {
        struct rte_mempool *rx_mp;       /**< Pool pointer for port RX mbufs */
    } q[NB_MAX_PORTS][NB_RX_QUEUES];
    struct rte_mempool *pktmbuf_pool;
};

/* struct corresponding to a cache for one NIC port */
struct                  pcap_cache {
    struct rte_mbuf**   mbufs;
};

/* struct to store dpdk context */
struct                  dpdk_ctx {
    unsigned long       nb_mbuf; /* number of needed mbuf (see main.c) */
    unsigned long       mbuf_sz; /* wanted/needed size for the mbuf (see main.c) */
    unsigned long       pool_sz; /* mempool wanted/needed size (see main.c) */
    struct rte_mempool* pktmbuf_pool;

    /* pcap file caches */
    long int            pcap_sz; /* size of the capture */
    struct pcap_cache*  pcap_caches; /* tab of caches, one per NIC port */
};

enum thread_type {
    PCAP_THREAD = 0,
    STATS_THREAD,
    RECV_THREAD
};

/* struct to store threads context */
struct                  thread_ctx {
    sem_t*              sem;
    sem_t*              sem_stop;
    pthread_t           thread;
    int                 tx_port_id; /* assigned tx port id */
    int                 rx_port_id; /* assigned tx port id */
    int                 nbruns;
    unsigned int        nb_pkt;
    int                 nb_tx_queues;
    int                 nb_tx_queues_start;
    int                 nb_tx_queues_end;
    int               max_mpps;
    /* results */
    double              duration;
    unsigned int        total_drop;
    unsigned int        total_drop_sz;
    struct pcap_cache*  pcap_cache;
    FILE*               csv_ptr;
    int                 slow_mode;
    int                 timeout;
    enum thread_type    t_type;
    unsigned int        thread_id;
};

struct                  pcap_ctx {
    int                 fd;
    unsigned int        nb_pkts;
    unsigned int        max_pkt_sz;
    size_t              cap_sz;
    unsigned int        tx_queues;
};

/*
  FUNC PROTOTYPES
*/

/* CPUS.C */
int                 init_cpus(const struct cmd_opts* opts, struct cpus_bindings* cpus);

/* DPDK.C */
int                 init_dpdk_eal_mempool(const struct cmd_opts* opts,
                                          const struct cpus_bindings* cpus,
                                          struct dpdk_ctx* dpdk_cfgs, unsigned int pcap_num);
int                 init_dpdk_ports(struct cpus_bindings* cpus, const struct cmd_opts* opts, unsigned int needed_cpus);
void*               myrealloc(void* ptr, size_t new_size);
int                 start_tx_threads(const struct cmd_opts* opts,
                                     const struct cpus_bindings* cpus,
                                     const struct dpdk_ctx* dpdk,
                                     const struct pcap_ctx *pcap);
int                 start_all_threads(const struct cmd_opts* opts,
                                     const struct cpus_bindings* cpus,
                                     const struct dpdk_ctx *dpdk_cfgs,
                                     const struct pcap_ctx *pcap_cfgs,
                                     unsigned int pcap_num);
struct thread_ctx * start_stats_threads(const struct cmd_opts* opts,
                                        const struct cpus_bindings* cpus);
void                dpdk_cleanup(struct dpdk_ctx* dpdk, struct cpus_bindings* cpus);
bool                str_in_list(const char *str, char **list, int len);

/* PCAP.C */
int                 preload_pcap(const struct cmd_opts* opts, struct pcap_ctx* pcap, unsigned int pcap_num);
int                 load_pcap(const struct cmd_opts* opts, struct pcap_ctx* pcap,
                              const struct cpus_bindings* cpus, struct dpdk_ctx* dpdk,
                              unsigned int needed_cpus);
void                clean_pcap_ctx(struct pcap_ctx* pcap);

/* UTILS.C */
char*               nb_oct_to_human_str(float size);
unsigned int        get_next_power_of_2(const unsigned int nb);

#endif /* __COMMON_H__ */
