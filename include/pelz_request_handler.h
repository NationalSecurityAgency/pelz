/*
 * pelz_data_handler.h
 */

#ifndef INCLUDE_PELZ_REQUEST_HANDLER_H_
#define INCLUDE_PELZ_REQUEST_HANDLER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "charbuf.h"

//The maxim key length
#define MAX_KEY_LEN 1024
#define MAX_SOC_DATA_SIZE 1024

typedef enum
{ REQ_UNK = 0, REQ_ENC = 1, REQ_DEC = 2 } RequestType;

typedef enum
{ ASCII = 0, HEX = 1 } FormatType;

typedef enum
{ REQUEST_OK, KEK_LOAD_ERROR, KEY_OR_DATA_ERROR, ENCRYPT_ERROR, DECRYPT_ERROR, REQUEST_TYPE_ERROR } RequestResponseStatus;

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * <pre>
 * Wrapper function that handles making the right function call to pass
 * a request to either the SGX-enabled key table or the regular key table.
 * <pre>
 *
 * @param[in] request_type the type of the request (encrypt or decrypt)
 * @param[in] key_id       the key_id of the key to be used for the request
 * @param[in] data_in      the input data
 * @param[out] output      a pointer to a charbuf to hold the output, will
 *                         be created inside the call
 *
 * @return REQUEST_OK on success, an error message indicating the type of
 *                    error otherwise.
 */
  RequestResponseStatus pelz_request_handler(RequestType request_type, charbuf key_id, charbuf data_in, charbuf * output);

#ifdef __cplusplus
}
#endif
#endif                          /* INCLUDE_PELZ_REQUEST_HANDLER_H_ */
