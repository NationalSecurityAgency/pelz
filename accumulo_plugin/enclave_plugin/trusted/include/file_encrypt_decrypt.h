/*
 * file_encrypt_decrypt.h
 */

#ifndef INCLUDE_FILE_ENCRYPT_DECRYPT_H_
#define INCLUDE_FILE_ENCRYPT_DECRYPT_H_

#include <stdio.h>
#include <stdlib.h>

#include "charbuf.h"

typedef enum
{ REQUEST_OK, KEK_NOT_LOADED, KEK_LOAD_ERROR, KEY_OR_DATA_ERROR, ENCRYPT_ERROR, DECRYPT_ERROR, REQUEST_TYPE_ERROR,
  CHARBUF_ERROR, SIGNATURE_ERROR
} RequestResponseStatus;

/**
 *
 * <pre>
 * Generates a random key of @param[in] key_size length.
 * <pre>
 *
 * @param[in] key_size Length of the random key to be genereated
 *
 * @return random key in charbuf
 */
charbuf key_gen(int key_size);

#endif /* INCLUDE_FILE_ENCRYPT_DECRYPT_H_ */
