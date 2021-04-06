/**
 * @file pelz_key_service.h
   @brief Provides global constants and macros for the key service
 */
#ifndef PELZ_KEY_SERVICE_H
#define PELZ_KEY_SERVICE_H

#include <stdlib.h>
#include <pelz_request_handler.h>

/**
 * <pre>
 * Pelz Key Service to transform the request received into a processed message back to the requester.
 * <pre>
 *
 * @param[in] request.chars  JSON string containing all request information need from client
 * @param[in] request.len  Length of JSON string request
 * @param[out] message.chars  JSON string containing response back to client
 * @param[out] message.len  Length of JSON string response
 * @param[in] key_table  Data Struct of Key Table to use in request processing
 * @param[out] key_table  Returned Data Struct of Key Table if table changed
 * @param[in] socket_id The integer identifier of the socket being used
 *
 * @return 0 on success, 1 on error
 */

int pelz_key_service(CharBuf request, CharBuf * message, KeyTable * key_table, int socket_id);

#endif
