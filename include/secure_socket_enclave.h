/*
 * @file secure_socket_enclave.h
 */

#ifndef INCLUDE_SECURE_SOCKET_ENCLAVE_H_
#define INCLUDE_SECURE_SOCKET_ENCLAVE_H_

#include <stdint.h>

uint32_t get_protection_key(uint32_t session_id, uint8_t **key_out, size_t *key_size);

#endif
