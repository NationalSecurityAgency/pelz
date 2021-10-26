/*
 * @file server_table.h
 * @brief Provides hash table for server cert lookup.
 */

#ifndef INCLUDE_SERVER_TABLE_H_
#define INCLUDE_SERVER_TABLE_H_

#include <stdbool.h>
#include <stdint.h>

#include "charbuf.h"

typedef union EntryData
{
  charbuf key;
  charbuf cert;
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
{ KEY, SERVER } TableType;

typedef enum
{ OK, ERR_REALLOC, ERR_BUF, RET_FAIL, NO_MATCH, MEM_ALLOC_FAIL } AddResponseStatus;

extern Table key_table;

extern Table server_table;

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
 * @param[in] id.chars The identifier assumed to be null terminated
 * @param[in] id.len Length of identifier
 * @param[out] index The index location of the lookup value
 * @param max_num_entries The max number of entries for the table that is default set at 100000
 *
 * @return 0 on success, 1 on failure
 */
  int table_lookup(int type, charbuf id, int *index);

#ifdef __cplusplus
}
#endif
#endif                          /* INCLUDE_SERVER_TABLE_H_ */
