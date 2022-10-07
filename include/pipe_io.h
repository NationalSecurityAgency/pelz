#ifndef INCLUDE_PIPE_IO_H_
#define INCLUDE_PIPE_IO_H_

#include "charbuf.h"
#include "pelz_request_handler.h"

#define PELZSERVICE "/tmp/pelzService"
#define PELZINTERFACE "/tmp/pelzInterface"

#ifdef __cplusplus
extern "C"
{
#endif
/**
 * <pre>
 * Writes a message to an already-opened FIFO pipe
 * </pre>
 *
 * @param[in] fd The FIFO pipe file descriptor
 * @param[in] msg Message to be sent along the pipe, null-terminated
 *
 * @return 0 if success, 1 if error
 */
  int write_to_pipe_fd(int fd, char *msg);

/**
 * <pre>
 * Writes a message to a FIFO pipe
 * </pre>
 *
 * @param[in] pipe The FIFO pipe name
 * @param[in] msg Message to be sent along the pipe, null-terminated
 *
 * @return 0 if success, 1 if error
 */
  int write_to_pipe(const char *pipe, char *msg);

/**
 * <pre>
 * Reads a message from the FIFO pipe
 * </pre>
 *
 * @param[in] pipe The FIFO pipe name
 * @param[out] msg Message sent along the pipe
 *
 * @return 0 if success, 1 if error
 */
  int read_from_pipe(const char *pipe, char **msg);

/**
 * <pre>
 * Reads a complete message from the interface FIFO pipe
 * </pre>
 *
 * @param[in] fd The FIFO pipe file descriptor number
 *
 * @return 0 if success, 1 if error
 */
  int read_listener(int fd);

/**
 * <pre>
 * Splits a message on the pelz pipe into tokens. Assumes a delimiter of ' '
 * </pre>
 *
 * @param[out] Reference to a double pointer intended to hold tokens
 * @param[out] The number of tokens output
 * @param[in]  The message to be tokenized
 * @param[in]  The length of the message being tokenized
 *
 * @return 0 if success, 1 if error
 */
  int tokenize_pipe_message(char ***tokens, size_t * num_tokens, char *message, size_t message_length);

/**
 * <pre>
 * Opens a FIFO pipe for reading
 * </pre>
 *
 * @param[in] name The FIFO pipe name
 *
 * @return the pipe's file descriptor number if success, -1 if error
 */
  int open_read_pipe(const char *name);

/**
 * <pre>
 * Opens a FIFO pipe for writing
 * </pre>
 *
 * @param[in] name The FIFO pipe name
 *
 * @return the pipe's file descriptor number if success, -1 if error
 */
  int open_write_pipe(const char *name);

/**
 * <pre>
 * Removes a FIFO pipe
 * </pre>
 *
 * @param[in] name The FIFO pipe name
 *
 * @return 0 if success, 1 if error
 */
  int remove_pipe(const char *name);

#ifdef __cplusplus
}
#endif

#endif
