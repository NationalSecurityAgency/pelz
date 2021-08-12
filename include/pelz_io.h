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
 * Check if the file path provided is valid.
 * </pre>
 *
 * @param[in] file_path The file path provided to be checked
 *
 * @return 0 if success, 1 if error
 */

  int encodeBase64Data(unsigned char *raw_data, size_t raw_data_size, unsigned char **base64_data, size_t * base64_data_size);

/**
 * <pre>
 * Reads an unsigned string encoded in base64 encoding and produces a string of raw bytes
 * </pre>
 *
 * @param[in] base64_data The data to be decoded
 * @param[in] base64data The size of the data to be decoded
 * @param[out] raw_data The raw bytes retrieved from base64_data
 * @param[out] raw_data_size The number of raw bytes
 *
 * @return 0 if success, 1 if error
 */
  int decodeBase64Data(unsigned char *base64_data, size_t b64_data_size, unsigned char **raw_data, size_t * raw_data_size);

/**
 * <pre>
 * Writes a message to the Pelz FIFO pipe
 * </pre>
 *
 * @param[in] msg Message to be sent along the pipe
 *
 * @return 0 if success, 1 if error
 */
  int write_to_pipe(char *msg);

/**
 * <pre>
 * Takes a message from the Pelz FIFO pipe then parses and executes the command
 * from message
 * </pre>
 *
 * @param[in] msg Message from the pipe to be parsed and executed
 *
 * @return 0 if success, 1 if error or exit service
 */
  int read_pipe(char *msg);
#ifdef __cplusplus
}
#endif

#endif
