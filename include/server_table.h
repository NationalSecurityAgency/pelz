/*
 * @file server_table.h
 * @brief Provides hash table for server cert lookup.
 */

#ifndef INCLUDE_SERVER_TABLE_H_
#define INCLUDE_SERVER_TABLE_H_

#include <stdbool.h>
#include <stdint.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "charbuf.h"

typedef struct ServerEntry
{
  charbuf server_id;
  X509 *cert;
} CertEntry;

typedef struct Certs
{
  CertEntry *entries;
  size_t num_entries;
  size_t mem_size;
} ServerTable;

typedef enum
{ OK, ERR_REALLOC, ERR_BUF, ERR_X509, RET_FAIL, NO_MATCH, MEM_ALLOC_FAIL } AddResponseStatus;

extern ServerTable server_table;

extern EVP_PKEY *private_pkey;

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * <pre>
 * This function performs lookup of certs by Identifier. Note the mutex needs to be unlocked by the function that calls this function.
 * </pre>
 *
 * @param[in] server_id.chars The server identifier assumed to be null terminated
 * @param[in] server_id.len Length of server identifier
 * @param[out] cert The X509 cert based from server_id
 * @param[in] server_table The server table that has the cert and is used for the lookup
 * @param[out] server_table The server table returned if cert was added
 * @param max_cert_entries The max number of cert entries for the table default set at 100000
 *
 * @return 0 on success, 1 on failure
 */
  int server_table_lookup(charbuf server_id, X509 ** cert);

#ifdef __cplusplus
}
#endif
#endif                          /* INCLUDE_SERVER_TABLE_H_ */
