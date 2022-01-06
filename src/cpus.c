/*
  SPDX-License-Identifier: BSD-3-Clause
  Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.
*/

#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <numa.h>
#include <unistd.h>

#include "main.h"

static int find_cpus_to_use(const struct cmd_opts* opts, struct cpus_bindings* cpus)
{
    unsigned int        i;
    unsigned int        cpu_cpt;

    if (!opts || !cpus)
        return (EINVAL);

    cpus->numacores = 1;
    cpus->numacore = opts->numacore;
    cpus->cpus_to_use = (void*)malloc(sizeof(*(cpus->cpus_to_use)) * (cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus + 1));
    if (cpus->cpus_to_use == NULL) {
        printf("%s: malloc failed.\n", __FUNCTION__);
        return (ENOMEM);
    }
#ifdef DEBUG
    printf("CPU cores to use:");
#endif /* DEBUG */
    for (i = 0, cpu_cpt = 0; i < cpus->nb_available_cpus; i++) {
        /* be sure that we get cores on the wanted numa */
        if (cpus->numacore == numa_node_of_cpu(i)) {
            cpus->cpus_to_use[cpu_cpt++] = i;
#ifdef DEBUG
            printf(" %i", i);
#endif /* DEBUG */
            if (cpu_cpt == cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus + 1) /* +1 to keep the first as fake master */
                break;
        } else cpus->numacores = 2;
    }
#ifdef DEBUG
    putchar('\n');
#endif /* DEBUG */
    if (cpu_cpt < cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus + 1) {
        printf("Wanted %i threads on numa %i, but found only %i CPUs.\n",
               cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus + 1, cpus->numacore, cpu_cpt);
        free(cpus->cpus_to_use);
        return (ENODEV);
    }
    return (0);
}

static uint64_t generate_mask(const struct cpus_bindings* cpus, uint8_t number)
{
    int      i;
    uint64_t coremask;

    if (!cpus)
        return (EINVAL);

    if ((0 == number) || ( 64 < number)) /* out of bounds */
        return (0);

    /* generate coremask */
    for (coremask = 0, i = 0; i < number; i++)
        coremask |= (uint64_t)(1 << cpus->cpus_to_use[i]);
#ifdef DEBUG
    printf("%s for %u cores -> 0x%lx\n", __FUNCTION__, number, coremask);
#endif /* DEBUG */
    return (coremask);
}

int init_cpus(const struct cmd_opts* opts, struct cpus_bindings* cpus)
{
    int ret;
    int i;

    if (!opts || !cpus)
        return (EINVAL);

    /* get the number of available cpus */
    cpus->nb_available_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);

    printf("available cpus: %i\n", cpus->nb_available_cpus);

    /* calculate the number of needed cpu cores */
    for (i = 0; opts->pcicards[i]; i++);
    cpus->nb_needed_pcap_cpus = i;
    printf("-> Needed cpus for PCAP: %u\n", cpus->nb_needed_pcap_cpus);

    if (opts->nb_stats > 0) {
        /* calculate the number of needed cpu cores for stats*/
        for (i = 0; opts->stats[i]; i++);
        cpus->nb_needed_stats_cpus = i;
        cpus->nb_needed_recv_cpus = i;
        printf("-> Needed cpus for stats: %u\n", cpus->nb_needed_stats_cpus);
        printf("-> Needed cpus for recv: %u\n", cpus->nb_needed_recv_cpus);
    }

    /* lookup on cores ID to use */
    ret = find_cpus_to_use(opts, cpus);
    if (ret)
        return (ret);

    /* generate coremask of selected cpu cores for dpdk init */
    /* NOTES: get an extra one to not use the 0/master one. TODO: do better :) */
    cpus->coremask = generate_mask(cpus, cpus->nb_needed_pcap_cpus + cpus->nb_needed_stats_cpus + cpus->nb_needed_recv_cpus + 1);
    if (!cpus->coremask)
        return (EINVAL);
    return (0);
}
