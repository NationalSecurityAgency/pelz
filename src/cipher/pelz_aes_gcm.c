/**
 * @file  pelz_aes_gcm.c
 *
 * @brief Implements AES GCM for pelz.
 */

#include "cipher/pelz_cipher.h"
#include "cipher/pelz_aes_gcm.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "memory_util.h"

//############################################################################
// aes_gcm_encrypt()
//############################################################################
int pelz_aes_gcm_encrypt(unsigned char* key,
			 size_t key_len,
			 unsigned char* plain,
			 size_t plain_len,
			 cipher_data_t* cipher_data)
{
  
  // Setting these here so we don't have to if we error out
  // before getting to them.
  cipher_data->cipher_len = 0;
  cipher_data->cipher = NULL;

  cipher_data->iv_len = 0;
  cipher_data->iv = NULL;

  cipher_data->tag_len = 0;
  cipher_data->tag = NULL;
  
  // validate non-NULL and non-empty encryption key specified
  if (key == NULL || key_len == 0)
  {
    return 1;
  }

  // validate non-NULL input plaintext buffer specified
  if (plain == NULL || plain_len == 0)
  {
    return 1;
  }

  // variable to hold length of resulting CT - OpenSSL insists this be an int
  int ciphertext_len = 0;

  // initialize the cipher context to match cipher suite being used
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    return 1;
  }
  int init_result = 0;

  switch (key_len)
  {
  case 16:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    break;
  case 24:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
    break;
  case 32:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    break;
  default:
    break;
  }
  if (!init_result)
  {
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // Create the IV. At the moment if you ask Pelz to encrypt for you
  // it'll only use the default IV length, but decrypt will work
  // with any valid IV length.
  cipher_data->iv_len  = PELZ_GCM_IV_LEN;
  cipher_data->iv = malloc(cipher_data->iv_len);
  if(cipher_data->iv == NULL)
  {
    cipher_data->iv_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  if (RAND_bytes(cipher_data->iv, cipher_data->iv_len) != 1)
  {
    free(cipher_data->iv);
    cipher_data->iv = NULL;
    cipher_data->iv_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the IV length in the cipher context
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, cipher_data->iv_len, NULL))
  {
    free(cipher_data->iv);
    cipher_data->iv = NULL;
    cipher_data->iv_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the key and IV in the cipher context
  if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, cipher_data->iv))
  {
    free(cipher_data->iv);
    cipher_data->iv = NULL;
    cipher_data->iv_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // For GCM as we're using it with the tag and IV held separately
  // the ciphertext length matches the plaintext length.
  cipher_data->cipher_len = plain_len;
  cipher_data->cipher = malloc(cipher_data->cipher_len);
  if (cipher_data->cipher == NULL)
  {
    free(cipher_data->iv);
    cipher_data->iv = NULL;
    cipher_data->iv_len = 0;
    cipher_data->cipher_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  
  // encrypt the input plaintext, put result in the output ciphertext buffer
  if (!EVP_EncryptUpdate(ctx, cipher_data->cipher, &ciphertext_len, plain, plain_len))
  {
    free(cipher_data->cipher);
    free(cipher_data->iv);
    cipher_data->cipher = NULL;
    cipher_data->iv = NULL;
    cipher_data->cipher_len = 0;
    cipher_data->iv_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // verify that the resultant CT length matches the input PT length
  if ((size_t) ciphertext_len != plain_len)
  {
    free(cipher_data->cipher);
    free(cipher_data->iv);
    cipher_data->cipher = NULL;
    cipher_data->iv = NULL;
    cipher_data->cipher_len = 0;
    cipher_data->iv_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  cipher_data->tag_len = PELZ_GCM_TAG_LEN;
  cipher_data->tag = (unsigned char*)malloc(cipher_data->tag_len);
  if(cipher_data->tag == NULL)
  {
    free(cipher_data->cipher);
    free(cipher_data->iv);
    cipher_data->cipher = NULL;
    cipher_data->iv = NULL;
    cipher_data->cipher_len = 0;
    cipher_data->iv_len = 0;
    cipher_data->tag_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // OpenSSL requires a "finalize" operation. For AES/GCM no data is written.
  if (!EVP_EncryptFinal_ex(ctx, cipher_data->tag, &ciphertext_len))
  {
    free(cipher_data->cipher);
    free(cipher_data->iv);
    free(cipher_data->tag);
    cipher_data->cipher = NULL;
    cipher_data->tag = NULL;
    cipher_data->iv = NULL;
    cipher_data->cipher_len = 0;
    cipher_data->tag_len = 0;
    cipher_data->iv_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // get the AES/GCM tag value
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, cipher_data->tag_len, cipher_data->tag))
  {
    free(cipher_data->cipher);
    free(cipher_data->iv);
    free(cipher_data->tag);
    cipher_data->cipher = NULL;
    cipher_data->iv = NULL;
    cipher_data->tag = NULL;
    cipher_data->cipher_len = 0;
    cipher_data->iv_len = 0;
    cipher_data->tag_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // now that the encryption is complete, clean-up cipher context
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}

//############################################################################
// aes_gcm_decrypt()
//############################################################################
int pelz_aes_gcm_decrypt(unsigned char *key,
			 size_t key_len,
			 cipher_data_t cipher_data,
			 unsigned char** plain,
			 size_t* plain_len)
{
  // Setting here so we don't have to do anything if we
  // error out before getting to them.
  *plain_len = 0;
  *plain = NULL;
  
  // validate non-NULL and non-empty decryption key specified
  if (key == NULL || key_len == 0)
  {
    return 1;
  }

  // validate non-NULL and non-empty input ciphertext buffer specified
  if (cipher_data.cipher == NULL || cipher_data.cipher_len == 0)
  {
    return 1;
  }

  if(cipher_data.iv == NULL || cipher_data.iv_len == 0)
  {
    return 1;
  }

  if(cipher_data.tag == NULL || cipher_data.tag_len == 0)
  {
    return 1;
  }

  // variables to hold/accumulate length returned by EVP library calls
  //   - OpenSSL insists this be an int
  int len = 0;
  size_t plaintext_len = 0;

  // initialize the cipher context to match cipher suite being used
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    return 1;
  }
  int init_result = 0;

  switch (key_len)
  {
  case 16:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    break;
  case 24:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
    break;
  case 32:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    break;
  default:
    break;
  }
  if (!init_result)
  {
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set tag to expected tag passed in with input data
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, cipher_data.tag_len, cipher_data.tag))
  {
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the IV length in the cipher context
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, cipher_data.iv_len, NULL))
  {
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the key and IV in the cipher context
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, cipher_data.iv))
  {
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  *plain_len = cipher_data.cipher_len;
  *plain = malloc(*plain_len);
  if(*plain == NULL)
  {
    *plain_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  // decrypt the input ciphertext, put result in the output plaintext buffer
  if (!EVP_DecryptUpdate(ctx, *plain, &len, cipher_data.cipher, *plain_len))
  {
    free(*plain);
    *plain = NULL;
    *plain_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  plaintext_len += len;

  // 'Finalize' Decrypt:
  //   - validate that resultant tag matches the expected tag passed in
  //   - should produce no more plaintext bytes in our case
  if (EVP_DecryptFinal_ex(ctx, *plain + plaintext_len, &len) <= 0)
  {
    free(*plain);
    *plain = NULL;
    *plain_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  plaintext_len += len;

  // verify that the resultant PT length matches the input CT length
  if (plaintext_len != *plain_len)
  {
    free(*plain);
    *plain = NULL;
    *plain_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // now that the decryption is complete, clean-up cipher context used
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}
