/*
 * @file key_table.h
 * @brief Provides hash table for Key lookup.
 */

#ifndef INCLUDE_KEY_TABLE_H_
#define INCLUDE_KEY_TABLE_H_

#include <stdbool.h>

#include "charbuf.h"

typedef struct TableEntry
{
  charbuf key_id;
  charbuf key;
} KeyEntry;

typedef struct Keys
{
  KeyEntry *entries;
  size_t num_entries;
  size_t mem_size;
} KeyTable;

extern KeyTable key_table;

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * <pre>
 * This function to add values in hash table based on location in key_id.
 * </pre>
 *
 * @param[in] key_id.chars Key identifier assumed to be null terminated
 * @param[in] key_id.len The length of the key identifier
 * @param[out] key.chars The key value
 * @param[out] key.len The length of the key
 * @param[in] key_table The key table that the new key needs to be added to
 * @param[out] key_table The key table with the new added key
 *
 * @return 0 on success, 1 on error
 */
  int key_table_add(charbuf key_id, charbuf * key);

/**
 * <pre>
 * This function performs lookup of Keys by Identifier. Note the mutex needs to be unlocked by the function that calls this function.
 * </pre>
 *
 * @param[in] key_id.chars The key identifier assumed to be null terminated
 * @param[in] key_id.len Length of Key Identifier
 * @param[out] key.chars The key value
 * @param[out] key.len The length of the key
 * @param[in] key_table The key table that has the key and is used for the lookup
 * @param[out] key_table The key table returned if key was added
 * @param max_key_entries The max number of key entries for the table default set at 100000
 *
 * @return 0 on success, 1 on failure
 */
  int key_table_lookup(charbuf key_id, charbuf * key);

#ifdef __cplusplus
}
#endif
#endif                          /* INCLUDE_KEY_TABLE_H_ */
