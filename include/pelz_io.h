#ifndef INCLUDE_PELZ_IO_H_
#define INCLUDE_PELZ_IO_H_

#include "charbuf.h"
#include "key_table.h"
#include "pelz_request_handler.h"

#ifdef __cplusplus
extern "C"
{
#endif
/**
 * <pre>
 * This function creates a new charbuf that contains the file extension of a file name sting in a charbuf
 * </pre>
 *
 * @param[in] buf The charbuf that contains the file name string
 * @param[out] ext The integer representation of the file extension type
 *
 * @return 0 on success, 1 on error
 */
  int get_file_ext(charbuf buf, int *ext);

/**
 * <pre>
 * Using key_id to check if there is actual file
 * <pre>
 *
 * @param[in] key_id The Identifier for the Key which is also file path and name
 *
 * @return 0 on success, 1 on error
 */
  int file_check(char *file_path);

/**
 * <pre>
 * Writes a message to the FIFO pipe
 * </pre>
 *
 * @param[in] pipe The FIFO pipe name
 * @param[in] msg Message to be sent along the pipe
 *
 * @return 0 if success, 1 if error
 */
  int write_to_pipe(char *pipe, char *msg);

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
  int read_from_pipe(char *pipe, char **msg);

/**
 * <pre>
 * Splites a message on the pelz pipe into tokens. Assumes a delimiter of ' '
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
 * Takes a message from the Pelz FIFO pipe then parses and executes the command
 * from message
 * </pre>
 *
 * @param[in] tokens Tokenized message from the pipe to be parsed and executed
 * @param[in] num_tokens The number of tokens output
 * @param[out] response Response to be sent to the second pipe 
 *
 * @return 0 if success, 1 if error or exit service
 */
  int parse_pipe_message(char **tokens, size_t num_tokens, char **response);
#ifdef __cplusplus
}
#endif

#endif
