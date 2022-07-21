/** 
 * @file  aes_keywrap_3394nopad.h
 *
 * @brief Provides access to OpenSSL's AES Key Wrap (RFC 3394) for pelz.
 */
#ifndef PELZ_AES_KEYWRAP_3394NOPAD_H_
#define PELZ_AES_KEYWRAP_3394NOPAD_H_

#include <stdlib.h>
#include "cipher/pelz_cipher.h"
/**
 * @brief This function uses OpenSSL to perform AES key wrap without padding
 *        (RFC 3394).
 *
 * @param[in]  key         The hex bytes containing the key -
 *                         pass in pointer to key value
 *
 * @param[in]  key_len     The length (in bytes) of the AES key
 *                         (must be 16, 24, of 32)
 *
 * @param[in]  plain       The plaintext data to be wrapped -
 *                         pass in pointer to input plaintext buffer
 *
 * @param[in]  plain_len   The length of the plaintext data in bytes
 *
 * @param[out] cipher_data A pointer to a cipher_data_t structure that will contain
 *                         the output ciphertext.
 *
 * @return 0 on success, 1 on error
 */
int pelz_aes_keywrap_3394nopad_encrypt(unsigned char *key,
				       size_t key_len,
				       unsigned char *plain,
				       size_t plain_len,
				       cipher_data_t* cipher_data);

/**
 * @brief This function uses OpenSSL to perform AES key unwrap without padding
 *        (RFC 3394).
 *
 * @param[in]  key         The hex bytes containing the key -
 *                         pass in pointer to key value
 *
 * @param[in]  key_len     The length (in bytes) of the AES key
 *                         (must be 16, 24, or 32)
 *
 * @param[in] cipher_data  A cipher_data_t structure containing the
 *                         ciphertext to be decrypted.
 *
 * @param[out] plain       The output plaintext buffer -
 *                         pass as pointer to address of buffer
 *
 * @param[out] plain_len   The length in bytes of the output plaintext -
 *                         pass as pointer to length value
 *
 * @return 0 on success, 1 on error
 */
int pelz_aes_keywrap_3394nopad_decrypt(unsigned char *key,
				       size_t key_len,
				       cipher_data_t cipher_data,
				       unsigned char** plain,
				       size_t* plain_len);

#endif
