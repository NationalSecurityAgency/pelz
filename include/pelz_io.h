#ifndef INCLUDE_PELZ_IO_H_
#define INCLUDE_PELZ_IO_H_

#include "charbuf.h"
#include "key_table.h"
#include "pelz_request_handler.h"

#ifdef __cplusplus
extern "C" {
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
 * Load key from location stated by Key ID
 * <pre>
 *
 * @param[in] key_data.key_id The Key Identifier
 * @param[in] key_data.key_id_len Length of Key Identifier
 * @param[out] key_data.key The key value
 * @param[out] key_data.key_len The length of the key
 *
 * @return 0 on success, 1 on error
 */
#if !defined(SGX)
  int key_load(size_t key_id_len, unsigned char* key_id, size_t* key_len, unsigned char** key);
  void ocall_malloc(size_t size, char** buf);
#endif


/**
 * <pre>
 * URI parsing of Key ID per RFC 8089 (The "file" URI Scheme) and RFC 959 (FILE TRANSFER PROTOCOL (FTP)) with
 * RFC 1738 (Uniform Resource Locators) Section 3.1 (Common Internet Scheme Syntax).
 * File path will be assumed to be the absolute path to file for production but uses local path for testing.
 * <pre>
 *
 * @param[in] key_id The Key Identifier to be parsed
 * @param[out] uri.type The type of scheme used for key_id
 * @param[out] uri.auth The file authority
 * @param[out] uri.path The path to file that contains the key
 * @param[out] uri.file The file that contains the key
 * @param[out] uri.host The IP address for the key host server
 * @param[out] uri.port The port to access the key host server
 * @param[out] uri.url_path The location path on key host server
 *
 * @return 0 on success, 1 on error
 */
int key_id_parse(charbuf key_id, URIValues * uri);

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

#ifdef __cplusplus
}
#endif
  
#endif
