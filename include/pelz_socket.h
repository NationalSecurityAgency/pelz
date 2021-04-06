/**
 * @file pelz_key_socket.h
 * @brief Provides global constants and macros for  Pelz Key's socket feature
 */

#ifndef PELZ_KEY_SOCKET_H
#define PELZ_KEY_SOCKET_H

/**
 * The C libraries needed for Pelz Key socket
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <pelz_request_handler.h>

/**
 * <pre>
 * Initialization of the socket used by the pelz key service.
 * -Configure Local Address
 * -Create socket
 * -Bind socket to local address
 * <pre>
 *
 * @param[in] max_request Value for maxim request received at once
 * @param[out] socket_id Integer representation of listening socket
 *
 * @return 0 on success, 1 on error
 *
 */
int pelz_key_socket_init(int max_request, int *socket_listen_id);

/**
 * <pre>
 * Accepting connection from client for the socket used by the pelz key service.
 * -Wait for Connection
 * -Accepts Connection
 * <pre>
 *
 * @param[in] socket_listen_id Integer representation of listening socket
 * @param[out] socket_id Integer representation of socket
 *
 * @return 0 on success, 1 on error
 *
 */
int pelz_key_socket_accept(int socket_listen_id, int *socket_id);

/**
 * <pre>
 * Receiving request for pelz key service from database.
 * -Receiving Request
 * -Reading Request
 * -Returning Request
 * <pre>
 *
 * @param[in] socket_id Integer representation of socket
 * @param[out] message.chars The request for the pelz key service received from the database, should be passed to pelz key service for processing
 * @param[out] message.len The length of the request sent
 *
 * @return 0 on success, 1 on error
 *
 */
int pelz_key_socket_recv(int socket_id, CharBuf * message);

/**
 * <pre>
 * Sending processed request as response to database
 * -Start with processed message
 * -Send response
 * <pre>
 *
 * @param[in] socket_id Integer representation of socket
 * @param[in] response.chars The processed request to be sent back to the database
 * @param[in] response.len The length of the processed request
 * 
 * @return 0 on success, 1 on error
 *
 */
int pelz_key_socket_send(int socket_id, CharBuf response);

/**
 * <pre>
 * Check for client connection.
 * <pre>
 *
 * @param[in] socket_id Integer representation of socket
 *
 * @return 0 on socket open, 1 on socket close
 *
 */
int pelz_key_socket_check(int socket_id);

/**
 * <pre>
 * Closing client connection.
 * -Close Connection
 * <pre>
 *
 * @param[in] socket_id Integer representation of socket
 *
 * @return 0 on success, 1 on error
 *
 */
int pelz_key_socket_close(int socket_id);

/**
 * <pre>
 * Closing listening socket for the pelz key service.
 * -Close Socket
 * <pre>
 *
 * @param[in] socket_listen_id Integer representation of listening socket
 *
 * @return 0 on success, 1 on error
 *
 */
int pelz_key_socket_teardown(int *socket_listen_id);

#endif
