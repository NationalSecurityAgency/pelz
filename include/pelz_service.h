/**
 * @file pelz_key_service.h
   @brief Provides global constants and macros for the key service
 */
#ifndef PELZ_KEY_SERVICE_H
#define PELZ_KEY_SERVICE_H

#include <stdbool.h>
#include <stdlib.h>

#include "pelz_request_handler.h"

extern bool global_pipe_reader_active;

/**
 * <pre>
 * Implements the pelz_service which listens on a specifed port for
 * requests and then handles them.
 * <pre>
 *
 * @param[in] max_requests  the maximum number of simultaneous socket connections
 * @param[in] port_open     the port number non-attested connections
 * @param[in] port_attested the port number for attested connections
 * @param[in] secure        value to determine if attestation only connection
 *
 * @returns 0 on success, 1, on error
 */
int pelz_service(int max_requests, int port_open, int port_attested, bool secure);

#endif
