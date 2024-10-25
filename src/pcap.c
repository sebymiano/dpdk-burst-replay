/*
  SPDX-License-Identifier: BSD-3-Clause
  Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.
*/

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "main.h"

#define MAX_PKT_SZ (1024 * 64) /* 64ko */

/*
  PCAP file header
*/
#define PCAP_MAGIC (0xa1b2c3d4)
#define PCAP_MAJOR_VERSION (2)
#define PCAP_MINOR_VERSION (4)
#define PCAP_SNAPLEN (262144)
#define PCAP_NETWORK (1) /* ethernet layer */
typedef struct pcap_hdr_s {
    uint32_t magic_number;  /* magic number */
    uint16_t version_major; /* major version number */
    uint16_t version_minor; /* minor version number */
    int32_t thiszone;       /* GMT to local correction */
    uint32_t sigfigs;       /* accuracy of timestamps */
    uint32_t snaplen;       /* max length of captured packets, in octets */
    uint32_t network;       /* data link type */
} __attribute__((__packed__)) pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;   /* timestamp seconds */
    uint32_t ts_usec;  /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
} __attribute__((__packed__)) pcaprec_hdr_t;

int check_pcap_hdr(const int fd) {
    pcap_hdr_t pcap_h;
    size_t nb_read;

    nb_read = read(fd, &pcap_h, sizeof(pcap_h));
    if (nb_read != sizeof(pcap_h))
        return (EIO);
    if (pcap_h.magic_number != PCAP_MAGIC ||
        pcap_h.version_major != PCAP_MAJOR_VERSION ||
        pcap_h.version_minor != PCAP_MINOR_VERSION) {
        log_error("check failed. magic (0x%.8x), major: %u, minor: %u",
                  pcap_h.magic_number, pcap_h.version_major,
                  pcap_h.version_minor);
        return (EPROTO);
    }
    return (0);
}

int add_pkt_to_cache(const struct dpdk_ctx* dpdk,
                     const int cache_index,
                     const unsigned char* pkt_buf,
                     const size_t pkt_sz,
                     const unsigned int cpt,
                     const int nbruns) {
    struct rte_mbuf* m;

    if (!dpdk || !pkt_buf)
        return (EINVAL);

    m = rte_pktmbuf_alloc(dpdk->pktmbuf_pool);
    if (!m) {
        log_error("rte_pktmbuf_alloc failed. exiting.");
        return (ENOMEM);
    }
    rte_memcpy((char*)m->buf_addr, pkt_buf, pkt_sz);
    m->data_off = 0;
    m->data_len = m->pkt_len = pkt_sz;
    m->nb_segs = 1;
    m->next = NULL;

    /* set the refcnt to the wanted number of runs, avoiding to free
       mbuf struct on first tx burst */
    rte_mbuf_refcnt_set(m, nbruns);

    /* check that the crafted packet is valid */
    rte_mbuf_sanity_check(m, 1);

    /* assign new cached pkt to list */
    dpdk->pcap_caches[cache_index].mbufs[cpt] = m;
    return (0);
}

int preload_pcap(const struct cmd_opts* opts,
                 struct pcap_ctx* pcap,
                 unsigned int pcap_num) {
    unsigned char pkt_buf[MAX_PKT_SZ];
    pcaprec_hdr_t pcap_rechdr;
    struct stat s;
    unsigned int cpt;
    size_t nb_read;
    long int total_read;
    float percent;
    int ret;
    uint64_t pkt_sizes = 0;

    if (!opts || !pcap)
        return (EINVAL);

    /* open wanted file */
    pcap->fd = open(opts->traces[pcap_num].path, O_RDONLY);
    if (pcap->fd < 0) {
        log_error("open of %s failed: %s", opts->traces[pcap_num].path,
                  strerror(errno));
        return (errno);
    }

    pcap->tx_queues = opts->traces[pcap_num].tx_queues;

    /* check pcap header */
    ret = check_pcap_hdr(pcap->fd);
    if (ret)
        goto preload_pcapErrorInit;

    /* get file informations */
    ret = stat(opts->traces[pcap_num].path, &s);
    if (ret)
        goto preload_pcapErrorInit;
    s.st_size -= sizeof(pcap_hdr_t);
    log_info("preloading %s file (of size: %li bytes)",
             opts->traces[pcap_num].path, s.st_size);
    pcap->cap_sz = s.st_size;

    /* loop on file to read all saved packets */
    for (total_read = 0, cpt = 0;; cpt++) {
        /* get packet pcap header */
        nb_read = read(pcap->fd, &pcap_rechdr, sizeof(pcap_rechdr));
        if (!nb_read) /* EOF :) */
            break;
        else if (nb_read == (unsigned long)(-1)) {
            log_error("%s: read failed (%s)", __FUNCTION__, strerror(errno));
            ret = errno;
            goto preload_pcapError;
        } else if (nb_read != sizeof(pcap_rechdr)) {
            log_error("read pkt hdr misssize: %lu / %lu", nb_read,
                      sizeof(pcap_rechdr));
            goto preload_pcapError;
        }
        total_read += nb_read;

#ifdef DEBUG
        if (pcap_rechdr.incl_len != pcap_rechdr.orig_len)
            log_info("pkt %i size: %u/%u", cpt, pcap_rechdr.incl_len,
                     pcap_rechdr.orig_len);
#endif /* DEBUG */

        /* update max pkt size (to be able to calculate the needed memory) */
        if (pcap_rechdr.incl_len > pcap->max_pkt_sz)
            pcap->max_pkt_sz = pcap_rechdr.incl_len;

        pkt_sizes += pcap_rechdr.incl_len;

        /* get packet */
        nb_read = read(pcap->fd, pkt_buf, pcap_rechdr.incl_len);
        if (nb_read == (unsigned long)(-1)) {
            log_error("%s: read failed (%s)", __FUNCTION__, strerror(errno));
            ret = errno;
            goto preload_pcapError;
        } else if (nb_read != pcap_rechdr.incl_len) {
            log_error("read pkt %i payload misssize: %u / %u", cpt,
                      (unsigned int)nb_read, pcap_rechdr.incl_len);
            goto preload_pcapError;
        }
        total_read += nb_read;

        /* calcul & print progression every 1024 pkts */
        if ((cpt % 1024) == 0) {
            percent = 100 * (float)total_read / (float)s.st_size;
            log_info("\rfile read at %02.2f%%", percent);
        }
    }

    pcap->avg_pkt_sz = pkt_sizes / cpt;

preload_pcapError:
    percent = 100 * (float)total_read / (float)s.st_size;
    printf("%sfile read at %02.2f%%\n", (ret ? "\n" : "\r"), percent);
    printf(
        "read %u pkts (for a total of %li bytes). max paket length = %u bytes. "
        "avg packet size = %u\n",
        cpt, total_read, pcap->max_pkt_sz, pcap->avg_pkt_sz);
preload_pcapErrorInit:
    if (ret) {
        close(pcap->fd);
        pcap->fd = 0;
    } else
        pcap->nb_pkts = cpt;
    return (ret);
}

int load_pcap(const struct cmd_opts* opts,
              struct pcap_ctx* pcap,
              const struct cpus_bindings* cpus,
              struct dpdk_ctx* dpdk,
              unsigned int needed_pcap_cpus) {
    pcaprec_hdr_t pcap_rechdr;
    unsigned char pkt_buf[MAX_PKT_SZ];
    unsigned int cpt = 0;
    size_t nb_read;
    long int total_read = 0;
    float percent;
    unsigned int i;
    int ret;

    if (!opts || !pcap || !cpus || !dpdk)
        return (EINVAL);

    /* alloc needed pkt caches and bzero them */
    dpdk->pcap_caches =
        malloc(sizeof(*(dpdk->pcap_caches)) * (needed_pcap_cpus));
    if (!dpdk->pcap_caches) {
        log_error("malloc of pcap_caches failed.");
        return (ENOMEM);
    }
    bzero(dpdk->pcap_caches, sizeof(*(dpdk->pcap_caches)) * (needed_pcap_cpus));
    for (i = 0; i < needed_pcap_cpus; i++) {
        dpdk->pcap_caches[i].mbufs =
            malloc(sizeof(*(dpdk->pcap_caches[i].mbufs)) * pcap->nb_pkts);
        if (dpdk->pcap_caches[i].mbufs == NULL) {
            log_error("malloc of mbufs failed.");
            return (ENOMEM);
        }
        bzero(dpdk->pcap_caches[i].mbufs,
              sizeof(*(dpdk->pcap_caches[i].mbufs)) * pcap->nb_pkts);
    }

    /* seek again to the beginning */
    if (lseek(pcap->fd, 0, SEEK_SET) == (off_t)(-1)) {
        log_error("lseek failed (%s)", strerror(errno));
        ret = errno;
        goto load_pcapError;
    }
    ret = check_pcap_hdr(pcap->fd);
    if (ret)
        goto load_pcapError;

    log_info("-> Will cache %i pkts on %i caches.", pcap->nb_pkts,
             needed_pcap_cpus);
    for (; cpt < pcap->nb_pkts; cpt++) {
        /* get packet pcap header */
        nb_read = read(pcap->fd, &pcap_rechdr, sizeof(pcap_rechdr));
        if (!nb_read) /* EOF :) */
            break;
        else if (nb_read == (unsigned long)(-1)) {
            log_error("read failed (%s)", strerror(errno));
            ret = errno;
            goto load_pcapError;
        } else if (nb_read != sizeof(pcap_rechdr)) {
            log_error("read pkt hdr misssize: %u / %lu", (unsigned int)nb_read,
                      sizeof(pcap_rechdr));
            ret = EIO;
            goto load_pcapError;
        }
        total_read += nb_read;

        /* get packet */
        nb_read = read(pcap->fd, pkt_buf, pcap_rechdr.incl_len);
        if (nb_read == (unsigned long)(-1)) {
            log_error("read failed (%s)", strerror(errno));
            ret = errno;
            goto load_pcapError;
        } else if (nb_read != pcap_rechdr.incl_len) {
            log_error("read pkt %u payload misssize: %u / %u", cpt,
                      (unsigned int)nb_read, pcap_rechdr.incl_len);
            ret = EIO;
            goto load_pcapError;
        }
        total_read += nb_read;

        /* add packet to caches */
        for (i = 0; i < needed_pcap_cpus; i++) {
            ret =
                add_pkt_to_cache(dpdk, i, pkt_buf, nb_read, cpt, opts->nbruns);
            if (ret) {
                log_error("add_pkt_to_cache failed on pkt.");
                goto load_pcapError;
            }
        }

        /* calcul & print progression every 1024 pkts */
        if ((cpt % 1024) == 0) {
            percent = 100 * cpt / pcap->nb_pkts;
            printf("\rfile read at %02.2f%%", percent);
        }
    }

load_pcapError:
    percent = 100 * cpt / pcap->nb_pkts;
    printf("%sfile read at %02.2f%%\n", (ret ? "\n" : "\r"), percent);
    if (ret)
        printf("read %u pkts (for a total of %li bytes).\n", cpt, total_read);
    dpdk->pcap_sz = total_read;
    close(pcap->fd);
    pcap->fd = 0;
    return (ret);
}

void clean_pcap_ctx(struct pcap_ctx* pcap) {
    if (!pcap)
        return;

    if (pcap->fd) {
        close(pcap->fd);
        pcap->fd = 0;
    }
    return;
}
