/**
 * @file  cipher.c
 * @brief Implements the pelz ciphers.
 */

#include "cipher/pelz_cipher.h"

#include <string.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#include "cipher/pelz_aes_keywrap_3394nopad.h"
#include "cipher/pelz_aes_gcm.h"

// Check for supported OpenSSL version
//   - OpenSSL v1.1.x required for AES KeyWrap RFC5649 w/ padding
//   - OpenSSL v1.1.1 is a LTS version supported until 2023-09-11
//   - OpenSSL v1.1.0 is not a supported version after 2019-09-11
//   - OpenSSL v1.0.2 is not a supported version after 2019-12-31
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error OpenSSL version 1.1.1 or newer is required
#endif

// pelz_cipher_list[] - array of structs that is used to specify all valid
//                 (e.g., implemented and supported) symmetric cipher opetions
//
// The cipher names MUST be formatted <Algorithm>/<Mode>/<Padding>/<Key Size>
const cipher_t pelz_cipher_list[] = {
  {.cipher_name = "AES/KeyWrap/RFC3394NoPadding/256",
   .encrypt_fn = pelz_aes_keywrap_3394nopad_encrypt,
   .decrypt_fn = pelz_aes_keywrap_3394nopad_decrypt},

  {.cipher_name = "AES/KeyWrap/RFC3394NoPadding/192",
   .encrypt_fn = pelz_aes_keywrap_3394nopad_encrypt,
   .decrypt_fn = pelz_aes_keywrap_3394nopad_decrypt},

  {.cipher_name = "AES/KeyWrap/RFC3394NoPadding/128",
   .encrypt_fn = pelz_aes_keywrap_3394nopad_encrypt,
   .decrypt_fn = pelz_aes_keywrap_3394nopad_decrypt},
  
  {.cipher_name = "AES/GCM/NoPadding/256",
   .encrypt_fn = pelz_aes_gcm_encrypt,
   .decrypt_fn = pelz_aes_gcm_decrypt},

  {.cipher_name = "AES/GCM/NoPadding/192",
   .encrypt_fn = pelz_aes_gcm_encrypt,
   .decrypt_fn = pelz_aes_gcm_decrypt},

  {.cipher_name = "AES/GCM/NoPadding/128",
   .encrypt_fn = pelz_aes_gcm_encrypt,
   .decrypt_fn = pelz_aes_gcm_decrypt},
  
  {.cipher_name = NULL,
   .encrypt_fn = NULL,
   .decrypt_fn = NULL},
};

cipher_t pelz_get_cipher_t_from_string(char *cipher_string)
{
  cipher_t cipher = {.cipher_name = NULL,
    .encrypt_fn = NULL,
    .decrypt_fn = NULL
  };

  // if input string is NULL, just return initialized cipher_t struct
  if (cipher_string == NULL)
  {
    return cipher;
  }

  // go through cipher_list looking for user-specified cipher name
  size_t i = 0;

  while (pelz_cipher_list[i].cipher_name != NULL)
  {
    if (strncmp
        (pelz_cipher_list[i].cipher_name, cipher_string,
         strlen(pelz_cipher_list[i].cipher_name) + 1) == 0)
    {
      // found it, set cipher to this entry in cipher_list and stop looking
      cipher = pelz_cipher_list[i];
      break;
    }
    i++;
  }

  return cipher;
}

size_t pelz_get_key_len_from_cipher(cipher_t cipher)
{
  if (cipher.cipher_name == NULL)
  {
    return 0;
  }

  char *key_len_string = NULL;

  // The key length string is always after the last delimiter.
  key_len_string = strrchr(cipher.cipher_name, '/') + 1;
  if (key_len_string == NULL)
  {
    return 0;
  }

  int key_len = atoi(key_len_string);

  if (key_len <= 0)
  {
    return 0;
  }

  return (size_t) key_len;
}
