/**
 * @file pelz_aes_gcm.h
 *
 * @brief Provides access to OpenSSL's AES GCM implementation for pelz.
 */
#ifndef PELZ_AES_GCM_H
#define PELZ_AES_GCM_H

#include <stdlib.h>

/// Length of the AES/GCM tag.
/// We hard code 16 byte tags, which is the longest length supported by AES/GCM
#define PELZ_GCM_TAG_LEN 16

/// Length of the Initialization Vector (IV) used by AES/GCM.
/// We hard code 12 byte IVs, which is the recommended 
/// (see NIST SP 800-38D, section 5.2.1.1) length for AES/GCM IVs.
#define PELZ_GCM_IV_LEN 12

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief This function uses the AES-GCM implementation from OpenSSL to
 *        encrypt data.
 *
 * @param[in]  key         The hex bytes containing the key -
 *                         pass in pointer to key buffer
 *
 * @param[in]  key_len     The length of the key in bytes
 *                         (must be 16, 24, or 32)
 *
 * @param[in]  plain       The plaintext data to be encrypted -
 *                         pass in pointer to input plaintext data buffer)
 *
 * @param[in]  plain_len   The length, in bytes, of the plaintext data
 *
 * @param[out] cipher_data A pointer to a cipher_data_t structure that will contain:
 *                         - The ciphertext
 *                         - The IV
 *                         - The MAC tag.
 *
 * @return 0 on success, 1 on error
 */
int pelz_aes_gcm_encrypt(unsigned char *key,
			 size_t key_len,
			 unsigned char* plain,
			 size_t plain_len,
			 cipher_data_t* cipher_data);

/**
 * @brief This function uses the AES-GCM implementation from OpenSSL to
 *        decrypt data.
 *
 * @param[in]  key         The hex bytes containing the key -
 *                         pass in pointer to key buffer
 *
 * @param[in]  key_len     The length of the key in bytes
 *                         (must be 16, 24, or 32)
 *
 * @param[in]  cipher_data A cipher_data_t structure containing:
 *                         - The ciphertext
 *                         - The IV used to encrypt the ciphertext
 *                         - The MAC tag
 *
 * @param[out] plain       The output plaintext -
 *                         passed as pointer to address of output buffer
 *
 * @param[out] plain_len   The length in bytes of outData
 *                         passed as pointer to length value
 *
 * @return 0 on success, 1 on error
 */
int pelz_aes_gcm_decrypt(unsigned char *key,
			 size_t key_len,
			 cipher_data_t cipher_data,
			 unsigned char** plain,
			 size_t* plain_len);
#ifdef __cplusplus
}
#endif
#endif
