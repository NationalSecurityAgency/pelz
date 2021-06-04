/**
 * @file pelz_key_service.h
   @brief Provides global constants and macros for the key service
 */
#ifndef PELZ_KEY_SERVICE_H
#define PELZ_KEY_SERVICE_H

#include <stdlib.h>

#include "pelz_request_handler.h"

/**
 * <pre>
 * Implements the pelz_service which listens on a specifed port for
 * requests and then handles them.
 * <pre>
 *
 * @param[in] max_requests the maximum number of simultaneous socket connections
 *
 * @returns 0 on success, 1, on error
 */
int pelz_service(int max_requests);

#endif
