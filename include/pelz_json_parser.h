/*
 * json_parser.h
 */

#ifndef INCLUDE_JSON_PARSER_H_
#define INCLUDE_JSON_PARSER_H_

#include <stdio.h>
#include <string.h>
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
 * @param[out] cipher_name.chars The cipher name from the JSON request
 * @param[out] cipher_name.len The length of the cipher name variable
 * @param[out] iv.chars The IV from the JSON request (if present)
 * @param[out] iv.len The length of the IV.
 * @param[out] tag.chars The tag from the JSON request (if present)
 * @param[out] tag.len The length of the tag.
 * @param[out] data Data to Wrap or Unwrap
 * @param[out] data_len The length of the data variable
 * @param[out] request_sig.chars The digital signature on the request, if present
 * @param[out] request_sig.len The length of the digital signature on the request
 * @param[out] requestor_cert.chars The requestors certificate, if present
 * @param[out] requestor_cert.len The length of the requestors certificate.
 *
 * @return 0 on success, 1 on error
 *
 */
int request_decoder(charbuf request, RequestType * request_type, charbuf * key_id, charbuf* cipher_name, charbuf* iv, charbuf* tag, charbuf * data, charbuf * request_sig, charbuf * requestor_cert);

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
 * JSON Encoder for server message. Encoder will combine server message associated variables in single JSON message.
 * <pre>
 *
 * @param[in] request_type The type of the request for which this is the response
 * @param[in] key_id.chars The Key ID from the original JSON request
 * @param[in] key_id.len The length of the Key ID variable
 * @param[in] cipher_name.chars The name of the cipher used to process the request
 * @param[in] cipher_name.len The length of the cipher name.
 * @param[in] iv.chars The IV used to process the request, if required and present.
 * @param[in] iv.len The length fo the IV.
 * @param[in] tag.chars The MAC tag used to process the request, if required and present.
 * @param[in] tag.len The length of the MAC tag.
 * @param[in] data Data Wrapped or Unwrapped
 * @param[in] data_len The length of the data variable
 *
 * @param[out] message.chars JSON message to client
 * @param[out] message.len The length of JSON message
 *
 * @return 0 on success, 1 on error
 *
 */
int message_encoder(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf iv, charbuf tag, charbuf data, charbuf * message);

#endif /* INCLUDE_JSON_PARSER_H_ */
