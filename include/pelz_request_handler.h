/*
 * pelz_request_handler.h
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
{ REQ_UNK, REQ_ENC, REQ_DEC, REQ_ENC_SIGNED, REQ_DEC_SIGNED } RequestType;

typedef enum
{ REQUEST_OK, KEK_NOT_LOADED, KEK_LOAD_ERROR, KEY_OR_DATA_ERROR, ENCRYPT_ERROR, DECRYPT_ERROR, REQUEST_TYPE_ERROR,
  CHARBUF_ERROR
} RequestResponseStatus;

#endif /* INCLUDE_PELZ_REQUEST_HANDLER_H_ */
