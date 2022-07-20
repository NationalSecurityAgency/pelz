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
 * @param[out] iv          Unused parameter only present to provide a
 *                         consistent interface for all ciphers. 
 *                         Should be NULL, is ignored.
 * 
 * @param[out] cipher      The output ciphertext data -
 *                         pass as pointer to address of buffer
 *
 * @param[out] cipher_len  The length of the output ciphertext in bytes -
 *                         pass as pointer to length value
 *
 * @param[out] tag_len     Pointer to hold the length of iv.
 *                         Should be NULL, is ignored.
 *
 * @param[out] tag         Unused parameter only present to provide a
 *                         consistent interface for all ciphers.
 *                         Should be NULL, is ignored.
 * 
 * @param[out  tag_len     Pointer to hold the length of tag.
 *                         Should be NULL, is ignored.
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
 * @param[in]  iv          Unused parameter only present to provide a 
 *                         consistent interface for all ciphers.
 *                         Should be NULL, is ignored.
 * 
 * @param[in]  iv_len      The length of iv, is ignored.
 *
 * @param[in]  cipher      The encrypted data to be unwrapped -
 *                         pass in pointer to input buffer
 *
 * @param[in]  cipher_len  The length of the encrypted data in bytes
 *
 * @param[in]  tag         Unused parameter only present to provide a 
 *                         consistent interface for all ciphers.
 *                         Should be NULL, is ignored.
 *
 * @param[in]  tag_len     The length of tag, is ignored.
 *
 * @param[out] plian       The output plaintext buffer -
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
