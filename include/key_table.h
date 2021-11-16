/*
 * @file key_table.h
 * @brief Provides hash table for Key lookup.
 */

#ifndef INCLUDE_KEY_TABLE_H_
#define INCLUDE_KEY_TABLE_H_

#include <stdbool.h>

#include "charbuf.h"
#include "common_table.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * <pre>
 * This function to add values in hash table based on location in key_id.
 * </pre>
 *
 * @param[in] key_id.chars Key identifier
 * @param[in] key_id.len The length of the key identifier
 * @param[out] key.chars The key value
 * @param[out] key.len The length of the key
 * @param[in] key_table The key table that the new key needs to be added to
 * @param[out] key_table The key table with the new added key
 *
 * @return 0 on success, 1 on error
 */
  int key_table_add(charbuf key_id, charbuf * key);

#ifdef __cplusplus
}
#endif
#endif                          /* INCLUDE_KEY_TABLE_H_ */
