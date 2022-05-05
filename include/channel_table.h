/*
 * @file channel_table.h
 * @brief Pr
 */

#ifndef INCLUDE_CHANNEL_TABLE_H_
#define INCLUDE_CHANNEL_TABLE_H_

#include <stdbool.h>
#include <stdint.h>

#include "charbuf.h"

typedef struct ChannalKeyTable
{
  charbuf *chan_key;
  size_t num_entries;
} ChanTable;

extern ChanTable channal_table;

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * <pre>
 * This function adds a channel key to the channal table at index specified by socket_id. Note the mutex needs to be unlocked by the function that calls this function.
 * </pre>
 *
 * @param[in] socket_id Index location for the channel key
 * @param[in] key.chars Table value for the channel key
 * @param[in] key.len   Length of cahnnel key value
 *
 * @return OK on success, an error message indicating the type of
 *                    error otherwise.
 */
  TableResponseStatus add_chan_key(int socket_id, charbuf key);

/**
 * <pre>
 * This function gets the channel key from the channel table. Note the mutex needs to be unlocked by the function that calls this function.
 * </pre>
 *
 * @param[in]  socket_id Index location for the channel key
 * @param[out] key.chars Table value for the channel key
 * @param[out] key.len   Length of channel key value
 *
 * @return OK on success, an error message indicating the type of
 *                    error otherwise.
 */
  TableResponseStatus get_chan_key(int socket_id, charbuf key);

/**
 * <pre>
 * This function clears the channel key from the channel table. Note the mutex needs to be unlocked by the function that calls this function.
 * </pre>
 *
 * @param[in]  socket_id Index location for the channel key to clear
 *
 * @return OK on success, an error message indicating the type of
 *                    error otherwise.
 */
  TableResponseStatus clear_chan_key(int socket_id);

#ifdef __cplusplus
}
#endif
#endif                          /* INCLUDE_COMMON_TABLE_H_ */
