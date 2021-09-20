/*
 * @file server_table.h
 * @brief Provides hash table for server cert lookup.
 */

#ifndef INCLUDE_SERVER_TABLE_H_
#define INCLUDE_SERVER_TABLE_H_

#include <stdbool.h>

#include "charbuf.h"

typedef struct ServerEntry
{
  charbuf server_id;
  charbuf cert;
} CertEntry;

typedef struct Certs
{
  CertEntry *entries;
  size_t num_entries;
  size_t mem_size;
} ServerTable;

extern ServerTable server_table;

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * <pre>
 * This function to add values in hash table based on location in server_id.
 * </pre>
 *
 * @param[in] server_id.chars Server identifier assumed to be null terminated
 * @param[in] server_id.len The length of the server identifier
 * @param[out] cert.chars The cert value
 * @param[out] cert.len The length of the cert
 * @param[in] server_table The server table that the new cert needs to be added to
 * @param[out] server_table The server table with the new added cert
 *
 * @return 0 on success, 1 on error
 */
  int server_table_add(charbuf server_id, charbuf * cert);

/**
 * <pre>
 * This function performs lookup of certs by Identifier. Note the mutex needs to be unlocked by the function that calls this function.
 * </pre>
 *
 * @param[in] server_id.chars The server identifier assumed to be null terminated
 * @param[in] server_id.len Length of server identifier
 * @param[out] cert.chars The cert value
 * @param[out] cert.len The length of the cert
 * @param[in] server_table The server table that has the cert and is used for the lookup
 * @param[out] server_table The server table returned if cert was added
 * @param max_cert_entries The max number of cert entries for the table default set at 100000
 *
 * @return 0 on success, 1 on failure
 */
  int server_table_lookup(charbuf server_id, charbuf * cert);

#ifdef __cplusplus
}
#endif
#endif                          /* INCLUDE_SERVER_TABLE_H_ */
