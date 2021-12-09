/*
 * test_helper_functions.h
 */

#ifndef TEST_HELPER_FUNCTIONS_H_
#define TEST_HELPER_FUNCTIONS_H_

#include "charbuf.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/**
 * <pre>
 * This function creates a new charbuf that contains the contents of two character strings
 * </pre>
 *
 * @param[in] prefix The character string of the key_id without current working directory prefix (schema notation)
 * @param[in] postfix The character string of the key_id without current working directory postfix (file path)
 *
 * @return charbuf copy of key_id with current working directory
 */
charbuf copy_CWD_to_id(const char *prefix, const char *postfix);

int kmyth_sgx_unseal_nkl(uint8_t * input, size_t input_len, uint64_t * handle);
size_t retrieve_from_unseal_table(uint64_t handle, uint8_t ** buf);
int enclave_retrieve_key(EVP_PKEY * enclave_sign_privkey, X509 * peer_cert);

#endif /* TEST_HELPER_FUNCTIONS_H_ */
