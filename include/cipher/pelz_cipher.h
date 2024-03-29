/**
 * @file  cipher.h
 *
 * @brief Provides structures, constants, and utilities for pelz
 *        symmetric ciphers.
 */

#ifndef PELZ_CIPHER_H
#define PELZ_CIPHER_H

#include <stddef.h>

typedef struct {
  unsigned char* cipher;
  size_t cipher_len;
  unsigned char* iv;
  size_t iv_len;
  unsigned char* tag;
  size_t tag_len;
} cipher_data_t;

/**
 * All data encryption methods must be implemented with encrypt
 * functions matching this declaration.
 *
 * Ciphers that do not require some of these arguments should ignore them.
 *
 * @param[in]  key         The hex bytes containing the key -
 *                         pass in pointer to key buffer
 *
 * @param[in]  key_len     The length of the key in bytes
 *
 * @param[in]  plain       The data to be encrypted -
 *                         pass in pointer to input data buffer
 *
 * @param[in]  plain_len   The length of plain in bytes
 *
 * @param[out] cipher_data A pointer to a cipher_data_t structure to hold all
 *                         outputs of the encryption. This includes:
 *                         - The output ciphertext
 *                         - The IV (if necessary)
 *                         - The MAC tag (if necessary)
 *
 * @return 0 on success, 1 on error.
 */
typedef int (*encrypt_cipher) (unsigned char *key,
			       size_t key_len,
			       unsigned char *plain,
			       size_t plain_len,
			       cipher_data_t* cipher_data);

/**
 * All data decryption methods must be implemented with decrypt
 * functions matching this declaration.
 *
 * Ciphers that do not require some of these arguments should ignore them.
 *
 * @param[in]  key         The hex bytes containing the key -
 *                         pass in pointer to key buffer
 *
 * @param[in]  key_len     The length of the key in bytes
 * 
 * @param[in]  cipher_data A cipher_data_st structure containing all data
 *                         required for decryption. This includes:
 *                         - The ciphertext
 *                         - The IV (if necessary)
 *                         - The MAC tag (if necessary)
 *
 * @param[out] plain       The output data -
 *                         pass in pointer to address of output buffer
 *
 * @param[out] plain_len   The length of the output data in bytes
 *                         pass as pointer to length value
 *

 *
 * @return 0 on success, 1 on error.
 */
typedef int (*decrypt_cipher) (unsigned char* key,
			       size_t key_len,
			       cipher_data_t cipher_data,
			       unsigned char** plain,
			       size_t* plain_len);


/**
 * cipher_t:
 *
 * The structure holding the information required to encrypt/decrypt
 * using a specified algorithm.
 */
typedef struct
{
  /** 
   * @brief A string representing the algorithm, which must be of the form 
   *        \<algorithm\>/\<mode\>/\<key length\>
  */
  char *cipher_name;

  /** @brief A pointer to the appropriate encryption function. */
  encrypt_cipher encrypt_fn;

  /** @brief A pointer to the appropriate decryption function. */
  decrypt_cipher decrypt_fn;
} cipher_t;

/**
 * @brief This function takes a putative cipher string and returns the
 *        corresponding cipher_t structure.
 *
 * @param[in]  cipher_string The string specifying the cipher
 *                           that was used to encrypt the data
 * 
 * @return The appropriate cipher_t structure, which has
 *         NULL cipher_name on failure.
 */
cipher_t pelz_get_cipher_t_from_string(char *cipher_string);

/**
 * @brief This function takes a cipher_t structure and parses the
 *        cipher_name string to return the key length in bits.
 *
 * @param[in]  cipher The relevant cipher_t structure
 *
 * @return The key length in bits, or 0 on failure
 */
size_t pelz_get_key_len_from_cipher(cipher_t cipher);

extern const cipher_t pelz_cipher_list[];
#endif /* CIPHER_H */
