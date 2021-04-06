/*
 * json_parser.h
 */

#ifndef INCLUDE_JSON_PARSER_H_
#define INCLUDE_JSON_PARSER_H_

#include <stdio.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <pelz_request_handler.h>

/**
 * <pre>
 * JSON Parser for client request. Parser will check request for validity and then separate request
 * into associated variables for processing.
 * <pre>
 *
 * @param[in] request.chars The request from the database to be parsed
 * @param[in] request.len The length of the request
 *
 * @param[out] request_type Type of Request to determine Encrypt or Decrypt
 * @param[out] key Key for Wrapper
 * @param[out] key_len The length of the key variable
 * @param[out] data Data to Wrap or Unwrap
 * @param[out] data_len The length of the data variable
 *
 * @return 0 on success, 1 on error
 *
 */
int request_decoder(CharBuf request, RequestValues * request_values);

/**
 * <pre>
 * JSON Parser for server message. Parser will combine server message associated variables in single JSON message.
 * <pre>
 *
 * @param[in] err_message Error message string to be sent back to client
 *
 * @param[out] message.chars JSON message to client
 * @param[out] message.len The length of JSON message
 *
 * @return 0 on success, 1 on error
 *
 */
int error_message_encoder(CharBuf * message, char *err_message);

/**
 * <pre>
 * JSON Parser for server message. Parser will combine server message associated variables in single JSON message.
 * <pre>
 *
 * @param[in] key Key for Wrapper
 * @param[in] key_len The length of the key variable
 * @param[in] data Data Wrapped or Unwrapped
 * @param[in] data_len The length of the data variable
 *
 * @param[out] message.chars JSON message to client
 * @param[out] message.len The length of JSON message
 *
 * @return 0 on success, 1 on error
 *
 */
int message_encoder(RequestValues request_values, CharBuf * message);

/**
 * <pre>
 * JSON Parser for client message. Parser will separate client message associated variables from a JSON message.
 * <pre>
 *
 * @param[in] json Parsed json string in cJSON format to be copied into request values
 *
 * @param[out] request_values.key_id.chars The key identifier
 * @param[out] request_values.key_id.len The length of key identifier
 * @param[out] request_values.data_in.chars The data to be encrypted
 * @param[out] request_values.data_in.len The length of data
 *
 * @return 0 on success, 1 on error
 *
 */
int encrypt_parser(cJSON * json, RequestValues * request_values);

/**
 * <pre>
 * JSON Parser for client message. Parser will separate client message associated variables from a JSON message.
 * <pre>
 *
 * @param[in] json Parsed json string in cJSON format to be copied into request values
 *
 * @param[out] request_values.key_id.chars The key identifier
 * @param[out] request_values.key_id.len The length of key identifier
 * @param[out] request_values.data_in.chars The data to be decrypted
 * @param[out] request_values.data_in.len The length of data
 *
 * @return 0 on success, 1 on error
 *
 */
int decrypt_parser(cJSON * json, RequestValues * request_values);

#endif /* INCLUDE_JSON_PARSER_H_ */
