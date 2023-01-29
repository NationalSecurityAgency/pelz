/*
 * @file common_table.h
 */

#ifndef INCLUDE_COMMON_TABLE_H_
#define INCLUDE_COMMON_TABLE_H_

#include <stdbool.h>
#include <stdint.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "charbuf.h"
#include "server_table.h"

#define MAX_MEM_SIZE 1000000

typedef union EntryData
{
  charbuf key;
  X509 *cert;
} Data;

typedef struct TableEntry
{
  charbuf id;
  Data value;
} Entry;

typedef struct CommonTable
{
  Entry *entries;
  size_t num_entries;
  size_t mem_size;
} Table;

typedef enum
{ 
  KEY,      /**< Table to store KEKs*/
  SERVER,   /**< Table to store server public certificates*/
  CA_TABLE, /**< Table to store CA certificates*/
  TEST      /**< Testing value for table functions*/
} TableType;

/// Enum to provide a return response status for table related functions.
typedef enum
{
  OK,             /**< OK             Function success*/
  ERR,            /**< ERR            Generic error response*/
  ERR_MEM,        /**< ERR_MEM        Error because set table memory allocation exceeded*/
  ERR_REALLOC,    /**< ERR_REALLOC    Table reallocation failure*/
  ERR_BUF,        /**< ERR_BUF        Charbuf creation error*/
  ERR_X509,       /**< ERR_X509       Error with X509*/
  RET_FAIL,       /**< RET_FAIL       Failure to return value from other function*/
  NO_MATCH,       /**< NO_MATCH       Look up found no match so function returned*/
  MEM_ALLOC_FAIL  /**< MEM_ALLOC_FAIL Failure to allocate initial memory*/
} TableResponseStatus;

extern Table key_table;

extern Table server_table;

extern pelz_identity_t pelz_id;

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * <pre>
 * This function performs lookup on a table by Identifier. Note the mutex needs to be unlocked by the function that calls this function.
 * </pre>
 *
 * @param[in] type The table type that used for the lookup
 * @param[in] id.chars The table value identifier
 * @param[in] id.len Length of identifier
 * @param[out] index The index location of the lookup value
 * @param max_num_entries The max number of entries for the table that is default set at 100000
 *
 * @return OK on success, an error message indicating the type of
 *                    error otherwise.
 */
  TableResponseStatus table_lookup(TableType type, charbuf id, int *index);

/**
 * <pre>
 * Helper function to get the table object corresponding to each TableType.
 * </pre>
 *
 * @param[in] type The table type
 *
 * @return A pointer to the table object, or NULL if the type does not match
 */
  Table *get_table_by_type(TableType type);

#ifdef __cplusplus
}
#endif
#endif                          /* INCLUDE_COMMON_TABLE_H_ */
