#ifndef CONFIG_YAML_H
#define CONFIG_YAML_H

#include <cyaml/cyaml.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "log.h"

static const cyaml_config_t config = {
    .log_fn = cyaml_log,            /* Use the default logging function. */
    .mem_fn = cyaml_mem,            /* Use the default memory allocator. */
    .log_level = CYAML_LOG_WARNING, /* Logging errors and warnings only. */
};

/******************************************************************************
 * C data structure for storing the configuration.
 ******************************************************************************/

typedef struct {
    char* path;
    int tx_queues;
} trace_t;

typedef struct {
    char* pci_id;
    char* file_name;
} stats_t;

typedef struct {
    trace_t* traces;
    unsigned traces_count;
    int numacore;
    int nbruns;
    int timeout;
    unsigned int nb_rx_queues;
    unsigned int nb_rx_cores;
    float max_mpps;
    float max_mbps;
    bool write_csv;
    bool convert_to_json;
    bool use_mac_filter;
    bool wait_enter;
    bool slow_mode;
    stats_t* stats;
    unsigned stats_count;
    char* send_port_pci;
    logs_t loglevel;
} config_t;

/* Mapping from "month" strings to flag values for schema. */
static const cyaml_strval_t loglevel_strings[] = {
    {"TRACE", LOG_TRACE},
    {"DEBUG", LOG_DEBUG},
    {"INFO", LOG_INFO},
    {"WARN", LOG_WARN},
    {"ERROR", LOG_ERROR},
    {"FATAL", LOG_FATAL},
};

/******************************************************************************
 * CYAML schema to tell libcyaml about both expected YAML and data structure.
 ******************************************************************************/

static const cyaml_schema_field_t trace_entry_schema[] = {
    CYAML_FIELD_STRING_PTR("path",
                           CYAML_FLAG_POINTER,
                           trace_t,
                           path,
                           0,
                           CYAML_UNLIMITED),
    CYAML_FIELD_INT("tx_queues", CYAML_FLAG_DEFAULT, trace_t, tx_queues),
    CYAML_FIELD_END};

static const cyaml_schema_value_t trace_entry = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, trace_t, trace_entry_schema),
};

static const cyaml_schema_field_t stats_entry_schema[] = {
    CYAML_FIELD_STRING_PTR("pci_id",
                           CYAML_FLAG_POINTER,
                           stats_t,
                           pci_id,
                           0,
                           CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("file_name",
                           CYAML_FLAG_POINTER,
                           stats_t,
                           file_name,
                           0,
                           CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t stats_entry = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, stats_t, stats_entry_schema),
};

static const cyaml_schema_field_t top_mapping_schema[] = {
    CYAML_FIELD_SEQUENCE("traces",
                         CYAML_FLAG_POINTER,
                         config_t,
                         traces,
                         &trace_entry,
                         0,
                         CYAML_UNLIMITED),
    CYAML_FIELD_INT("numacore", CYAML_FLAG_DEFAULT, config_t, numacore),
    CYAML_FIELD_INT("nbruns", CYAML_FLAG_DEFAULT, config_t, nbruns),
    CYAML_FIELD_INT("timeout", CYAML_FLAG_DEFAULT, config_t, timeout),
    CYAML_FIELD_FLOAT("max_mpps", CYAML_FLAG_DEFAULT, config_t, max_mpps),
    CYAML_FIELD_FLOAT("max_mbps", CYAML_FLAG_DEFAULT, config_t, max_mbps),
    CYAML_FIELD_BOOL("write_csv", CYAML_FLAG_DEFAULT, config_t, write_csv),
    CYAML_FIELD_BOOL("convert_to_json", CYAML_FLAG_DEFAULT, config_t, convert_to_json),
    CYAML_FIELD_BOOL("use_mac_filter", CYAML_FLAG_DEFAULT, config_t, use_mac_filter),
    CYAML_FIELD_BOOL("wait_enter", CYAML_FLAG_DEFAULT, config_t, wait_enter),
    CYAML_FIELD_BOOL("slow_mode", CYAML_FLAG_DEFAULT, config_t, slow_mode),
    CYAML_FIELD_UINT("nb_rx_queues",
                     CYAML_FLAG_DEFAULT,
                     config_t,
                     nb_rx_queues),
    CYAML_FIELD_UINT("nb_rx_cores", CYAML_FLAG_DEFAULT, config_t, nb_rx_cores),
    CYAML_FIELD_SEQUENCE("stats",
                         CYAML_FLAG_POINTER,
                         config_t,
                         stats,
                         &stats_entry,
                         0,
                         CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("send_port_pci",
                           CYAML_FLAG_POINTER,
                           config_t,
                           send_port_pci,
                           0,
                           CYAML_UNLIMITED),
    CYAML_FIELD_ENUM("loglevel",
                     CYAML_FLAG_DEFAULT,
                     config_t,
                     loglevel,
                     loglevel_strings,
                     CYAML_ARRAY_LEN(loglevel_strings)),
    CYAML_FIELD_END};

static const cyaml_schema_value_t top_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, config_t, top_mapping_schema),
};

#endif /* CONFIG_YAML_H */