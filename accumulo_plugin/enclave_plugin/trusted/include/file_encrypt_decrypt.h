/*
 * file_encrypt_decrypt.h
 */

#ifndef INCLUDE_FILE_ENCRYPT_DECRYPT_H_
#define INCLUDE_FILE_ENCRYPT_DECRYPT_H_

#include <stdio.h>
#include <stdlib.h>

#include "file_enc_dec.h"

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
