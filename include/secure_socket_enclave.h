/*
 * @file secure_socket_enclave.h
 */

#ifndef INCLUDE_SECURE_SOCKET_ENCLAVE_H_
#define INCLUDE_SECURE_SOCKET_ENCLAVE_H_

#include <stdint.h>

uint8_t * get_session_key(uint32_t session_id, size_t *key_size);

#endif
