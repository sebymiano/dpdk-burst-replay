/*
  SPDX-License-Identifier: BSD-3-Clause
  Copyright 2024 Sebastiano Miano, sebymiano. All rights reserved.
*/

#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "main.h"

static enum MHD_Result iterate_post(void *cls, enum MHD_ValueKind kind, const char *key,
                                    const char *filename, const char *content_type,
                                    const char *transfer_encoding, const char *data, uint64_t off,
                                    size_t size) {
    struct connection_info *conn_info = (struct connection_info *)cls;

    if ((strcmp(conn_info->endpoint, "/rate_mbps") == 0 || strcmp(conn_info->endpoint, "/rate_mpps") == 0)
        && strcmp(key, "rate") == 0) {
        char *endptr;
        float new_rate = strtof(data, &endptr);
        if (endptr == data || *endptr != '\0') {
            log_trace("Invalid rate value: %s", data);
            return MHD_NO; // Reject invalid rate
        }

        // Update rate depending on the endpoint
        struct http_shared_data *shared_data = conn_info->shared_data;
        pthread_mutex_lock(&shared_data->lock);
        if (strcmp(conn_info->endpoint, "/rate_mbps") == 0) {
            shared_data->rate_mbps = new_rate;
            log_trace("Updated rate_mbps to %f", new_rate);
        } else {
            shared_data->rate_mpps = new_rate;
            log_trace("Updated rate_mpps to %f", new_rate);
        }
        pthread_mutex_unlock(&shared_data->lock);
    } else {
        log_trace("Unknown key or endpoint: key=%s, endpoint=%s", key, conn_info->endpoint);
    }

    return MHD_YES;
}

static enum MHD_Result request_handler(void *cls, struct MHD_Connection *connection,
                                       const char *url, const char *method, const char *version,
                                       const char *upload_data, size_t *upload_data_size, void **con_cls) {
    struct http_shared_data *data = (struct http_shared_data *)cls;

    // Allocate connection-specific state on the first call
    if (*con_cls == NULL) {
        struct connection_info *conn_info = calloc(1, sizeof(struct connection_info));
        if (conn_info == NULL) {
            return MHD_NO; // Memory allocation failed
        }

        if (strcmp(method, MHD_HTTP_METHOD_POST) == 0 && 
           (strcmp(url, "/rate_mbps") == 0 || strcmp(url, "/rate_mpps") == 0)) {
            conn_info->post_processor = MHD_create_post_processor(connection, 1024, iterate_post, conn_info);
            if (conn_info->post_processor == NULL) {
                free(conn_info);
                return MHD_NO; // Post processor creation failed
            }
        }
        strncpy(conn_info->endpoint, url, sizeof(conn_info->endpoint) - 1);
        conn_info->response_code = MHD_HTTP_OK;
        conn_info->shared_data = data;
        *con_cls = conn_info;

        return MHD_YES; // Ready to receive upload data
    }

    struct connection_info *conn_info = *con_cls;

    if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
        if (conn_info->post_processor) {
            MHD_post_process(conn_info->post_processor, upload_data, *upload_data_size);
            if (*upload_data_size != 0) {
                *upload_data_size = 0; // Mark data as processed
                return MHD_YES;        // Continue processing
            }
            /* done with POST data, serve response */
            MHD_destroy_post_processor(conn_info->post_processor);
            conn_info->post_processor = NULL;
        } else if (strcmp(conn_info->endpoint, "/exit") == 0) {
            pthread_mutex_lock(&conn_info->shared_data->lock);
            conn_info->shared_data->exit = 1;
            pthread_mutex_unlock(&conn_info->shared_data->lock);
            pthread_cond_signal(&conn_info->shared_data->cond); // Notify the main thread to exit
        } else if (strcmp(conn_info->endpoint, "/start") == 0) {
            pthread_mutex_lock(&conn_info->shared_data->lock);
            conn_info->shared_data->start = 1;
            pthread_mutex_unlock(&conn_info->shared_data->lock);
            pthread_cond_signal(&conn_info->shared_data->cond); // Notify the main thread
        } else {
            const char *response = "Unknown endpoint.\n";
            struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response),
                                                                                (void *)response,
                                                                                MHD_RESPMEM_PERSISTENT);
            int ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, mhd_response);
            MHD_destroy_response(mhd_response);
            return ret;
        }
        
        // Send a response to the client
        const char *response = "Command processed successfully.\n";
        struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response),
                                                                            (void *)response,
                                                                            MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, mhd_response);
        MHD_destroy_response(mhd_response);

        return ret;
    }
    
    const char *response = "Unknown method.\n";
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response),
                                                                        (void *)response,
                                                                        MHD_RESPMEM_PERSISTENT);
    int ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, mhd_response);
    MHD_destroy_response(mhd_response);
    return ret;
}

struct MHD_Daemon *start_http_server(const struct cmd_opts* opts, struct http_shared_data* data) {
    struct MHD_Daemon *daemon;

    if (!opts)
        return (NULL);

    daemon = MHD_start_daemon(MHD_USE_POLL_INTERNAL_THREAD, opts->rest_server_port, NULL, NULL, &request_handler, data, MHD_OPTION_END);
    if (daemon == NULL) {
        log_error("Failed to start HTTP server on port %d", opts->rest_server_port);
        return (NULL);
    }

    log_info("HTTP server started on port %d", opts->rest_server_port);
    return (daemon);
}

int stop_http_server(struct MHD_Daemon *daemon) {
    if (daemon == NULL)
        return (-1);

    MHD_stop_daemon(daemon);
    return (0);
}