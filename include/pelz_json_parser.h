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
 * @param[out] key_id.chars The Key ID from the JSON request
 * @param[out] key_id.len The length of the Key ID variable
 * @param[out] data Data to Wrap or Unwrap
 * @param[out] data_len The length of the data variable
 *
 * @return 0 on success, 1 on error
 *
 */
int request_decoder(charbuf request, RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * request_sig, charbuf * requestor_cert);

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
int error_message_encoder(charbuf * message, const char *err_message);

/**
 * <pre>
 * JSON Parser for server message. Parser will combine server message associated variables in single JSON message.
 * <pre>
 *
 * @param[in] key_id.chars The Key ID from the JSON request
 * @param[in] key_id.len The length of the Key ID variable
 * @param[in] data Data Wrapped or Unwrapped
 * @param[in] data_len The length of the data variable
 *
 * @param[out] message.chars JSON message to client
 * @param[out] message.len The length of JSON message
 *
 * @return 0 on success, 1 on error
 *
 */
int message_encoder(RequestType request_type, charbuf key_id, charbuf data, charbuf * message);

/**
 * <pre>
 * JSON Parser for client message. Parser will separate client message associated variables from a JSON message.
 * <pre>
 *
 * @param[in] json Parsed json string in cJSON format to be copied into request values
 *
 * @param[out] key_id.chars The key identifier
 * @param[out] key_id.len The length of key identifier
 * @param[out] data.chars The data to be encrypted
 * @param[out] data.len The length of data
 *
 * @return 0 on success, 1 on error
 *
 */
int encrypt_parser(cJSON * json, charbuf * key_id, charbuf * data);

/**
 * <pre>
 * JSON Parser for client message. Parser will separate client message associated variables from a JSON message.
 * <pre>
 *
 * @param[in] json Parsed json string in cJSON format to be copied into request values
 *
 * @param[out] key_id.chars The key identifier
 * @param[out] key_id.len The length of key identifier
 * @param[out] data.chars The data to be decrypted
 * @param[out] data.len The length of data
 *
 * @return 0 on success, 1 on error
 *
 */
int decrypt_parser(cJSON * json, charbuf * key_id, charbuf * data);

/**
 * <pre>
 * JSON Parser for a signed message. Parser will separate client message associated variables from a JSON message.
 * <pre>
 *
 * @param[in] json Parsed json string in cJSON format to be copied into request values
 *
 * @param[out] request_sig.chars The user-supplied key
 * @param[out] request_sig.len The length of supplied key
 * @param[out] requestor_cert.chars The certificate of the user
 * @param[out] requestor_cert.len The length of certificate
 *
 * @return 0 on success, 1 on error
 *
 */
int signed_parser(cJSON * json, charbuf * request_sig, charbuf * requestor_cert);

#endif /* INCLUDE_JSON_PARSER_H_ */
