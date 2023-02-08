/**
 * @file  aes_keywrap_3394nopad.c
 *
 * @brief Implements AES Key Wrap with no padding (RFC 3394) for pelz.
 */

#include "cipher/pelz_cipher.h"
#include "cipher/pelz_aes_keywrap_3394nopad.h"
#include "pelz_enclave_log.h"

#include <openssl/evp.h>

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

//############################################################################
// aes_keywrap_3394nopad_encrypt()
//############################################################################
int pelz_aes_keywrap_3394nopad_encrypt(unsigned char *key,
				       size_t key_len,
				       unsigned char* plain,
				       size_t plain_len,
				       cipher_data_t* cipher_data)
{
  // Zero/null out so if we error out before setting them we don't have
  // to set them before returning.
  cipher_data->cipher_len = 0;
  cipher_data->cipher = NULL;

  cipher_data->iv_len = 0;
  cipher_data->iv = NULL;

  cipher_data->tag_len = 0;
  cipher_data->tag = NULL;
  
  // validate non-NULL and non-empty encryption key specified
  if (key == NULL || key_len == 0)
  {
    pelz_sgx_log(LOG_ERR, "no key data ... exiting");
    return 1;
  }

  // validate non-NULL, non-empty input plaintext buffer with a size that is
  // a multiple of eight (8) bytes greater than or equal to 16 was specified
  if (plain == NULL || plain_len == 0)
  {
    pelz_sgx_log(LOG_ERR, "no input data ... exiting");
    return 1;
  }
  if (plain_len < 16 || plain_len % 8 != 0)
  {
    pelz_sgx_log(LOG_ERR, "bad data size - not div by 8/min 16 bytes ... exiting");
    return 1;
  }
  if (plain_len > INT_MAX)
  {
    pelz_sgx_log(LOG_ERR, "Input cipher data cannot exceed INT_MAX bytes in size.");
    return 1;
  }
  // initialize the cipher context to match cipher suite being used
  //   - OpenSSL requires the WRAP_ALLOW flag be explicitly set to use key
  //     wrap modes through EVP.
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    pelz_sgx_log(LOG_ERR, "error creating AES Key Wrap cipher context ... exiting");
    return 1;
  }
  EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  int init_result = 0;

  switch (key_len)
  {
  case 16:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_128_wrap(), NULL, NULL, NULL);
    break;
  case 24:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_192_wrap(), NULL, NULL, NULL);
    break;
  case 32:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, NULL, NULL);
    break;
  default:
    pelz_sgx_log(LOG_ERR, "invalid key size");
  }
  if (!init_result)
  {
    pelz_sgx_log(LOG_ERR, "AES Key Wrap cipher context init error ... exiting");
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the encryption key in the cipher context
  if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL))
  {
    pelz_sgx_log(LOG_ERR, "error setting key ... exiting");
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // setup output ciphertext data buffer (outData):
  //   - an 8-byte integrity check value is prepended to input plaintext
  //   - the ciphertext output is the same length as the expanded plaintext
  cipher_data->cipher_len = plain_len + 8;
  cipher_data->cipher = (unsigned char *) malloc(cipher_data->cipher_len);
  if (cipher_data->cipher == NULL)
  {
    pelz_sgx_log(LOG_ERR, "malloc error for output ciphertext ... exiting");
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // track the ciphertext length separate from *cipher_len because we
  // know in advance what *cipher_len should be, but want to verify that
  // the output ciphertext length we actually end up with is as expected.
  //   - ciphertext_len: integer variable used to accumulate length result
  //   - tmp_len: integer variable used to get output size from EVP functions
  size_t ciphertext_len = 0;
  int tmp_len = 0;

  // encrypt (wrap) the input PT, put result in the output CT buffer
  // The type conversion on plain_len is safe because we know it is
  // less than INT_MAX.
  if (!EVP_EncryptUpdate(ctx, cipher_data->cipher, &tmp_len, plain, (int)plain_len) || tmp_len <= 0)
  {
    pelz_sgx_log(LOG_ERR, "encryption error ... exiting");
    free(cipher_data->cipher);
    cipher_data->cipher = NULL;
    cipher_data->cipher_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  ciphertext_len = (size_t)tmp_len;
  pelz_sgx_log(LOG_DEBUG, "key wrap produced output CT bytes");
  
  // OpenSSL requires a "finalize" operation
  if (!EVP_EncryptFinal_ex(ctx, (cipher_data->cipher) + ciphertext_len, &tmp_len) || tmp_len <= 0)
  {
    pelz_sgx_log(LOG_ERR, "finalization error ... exiting");
    free(cipher_data->cipher);
    cipher_data->cipher = NULL;
    cipher_data->cipher_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  ciphertext_len += (size_t)tmp_len;

  // verify that the resultant CT length matches expected (input PT length plus
  // eight bytes for prepended integrity check value)
  if (ciphertext_len != cipher_data->cipher_len)
  {
    pelz_sgx_log(LOG_ERR, "CT length error between expected and  actual bytes ... exiting");
    free(cipher_data->cipher);
    cipher_data->cipher = NULL;
    cipher_data->cipher_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // now that the encryption is complete, clean-up cipher context
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}

//############################################################################
// aes_keywrap_3394nopad_decrypt()
//############################################################################
int pelz_aes_keywrap_3394nopad_decrypt(unsigned char *key,
				       size_t key_len,
				       cipher_data_t cipher_data,
				       unsigned char** plain,
				       size_t* plain_len)
{
  // We set these now so if we error out before setting them we
  // don't have to zero/null them before returning.
  *plain_len = 0;
  *plain = NULL;
  
  // validate non-NULL and non-empty decryption key specified
  if (key == NULL || key_len == 0)
  {
    pelz_sgx_log(LOG_ERR, "no key data ... exiting");
    return 1;
  }

  // validate NULL and 0 length ivs and tags.
  if(cipher_data.iv != NULL || cipher_data.iv_len > 0 || cipher_data.tag != NULL || cipher_data.tag_len > 0)
  {
    pelz_sgx_log(LOG_ERR, "Unexpected non-NULL arguments to decryptor.");
    return 1;
  }
	     
  // verify non-NULL and non-empty input ciphertext buffer of a valid length
  // (multiple of eight bytes greater than or equal to 24 bytes)
  //
  // Note: 8 bytes (64 bits) is the size of a semiblock (half of the block
  //       size) for the AES block cipher and this no-pad version of AES keywrap
  //       requires the plaintext consist of an integer number of semiblocks.
  if (cipher_data.cipher == NULL || cipher_data.cipher_len == 0)
  {
    pelz_sgx_log(LOG_ERR, "no input data ... exiting");
    return 1;
  }
  if (cipher_data.cipher_len < 24)
  {
    pelz_sgx_log(LOG_ERR, "input data must be >= 24 bytes) ... exiting");
    return 1;
  }
  if (cipher_data.cipher_len % 8 != 0)
  {
    pelz_sgx_log(LOG_ERR, "bad data size - not div by 8/min 16 bytes ... exiting");
    return 1;
  }
  if (cipher_data.cipher_len > INT_MAX)
  {
    pelz_sgx_log(LOG_ERR, "bad data size, exceeds INT_MAX bytes ... exiting");
    return 1;
  }
  // initialize the cipher context to match cipher suite being used
  //   - OpenSSL requires the WRAP_ALLOW flag be explicitly set to use key
  //     wrap modes through EVP.
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    pelz_sgx_log(LOG_ERR, "error creating cipher context ... exiting");
    return 1;
  }
  EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  int init_result = 0;

  switch (key_len)
  {
  case 16:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_128_wrap(), NULL, NULL, NULL);
    break;
  case 24:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_192_wrap(), NULL, NULL, NULL);
    break;
  case 32:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, NULL, NULL);
    break;
  default:
    pelz_sgx_log(LOG_DEBUG, "invalid key length");
  }
  if (!init_result)
  {
    pelz_sgx_log(LOG_ERR, "AES Key Wrap cipher context init error ... exiting");
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  pelz_sgx_log(LOG_DEBUG, "AES Key Wrap (RFC3394NoPadding) cipher context");

  // set the decryption key in the cipher context
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL))
  {
    pelz_sgx_log(LOG_ERR, "error setting key ... exiting");
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // we know in advance what *outData_len should be, but want to verify that
  // the output plaintext length we actually end up matches the expected result
  //   - tmp_len: integer variable used to get output size from EVP functions
  int tmp_len = 0;

  // output data buffer (plain) will contain the decrypted plaintext, which
  // should be the same size as the input ciphertext data (original plaintext
  // plus prepended 8-byte integrity check value)
  *plain = (unsigned char *) malloc(cipher_data.cipher_len);
  if (*plain == NULL)
  {
    pelz_sgx_log(LOG_ERR, "malloc error for PT output ... exiting");
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // decrypt the input ciphertext, put result (with the prepended integrity
  // check value validated and removed) in the output plaintext buffer
  // The size conversion on cipher_data.cipher_len is safe because we've already
  // checked it does not exceed INT_MAX.
  if (!EVP_DecryptUpdate(ctx, *plain, &tmp_len, cipher_data.cipher, (int)cipher_data.cipher_len) || tmp_len <= 0)
  {
    pelz_sgx_log(LOG_ERR, "key unwrapping error ... exiting");
    free(*plain);
    *plain = NULL;
    *plain_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  *plain_len = (size_t)tmp_len;
  pelz_sgx_log(LOG_DEBUG, "key unwrap produced PT bytes");

  // "finalize" decryption
  if (!EVP_DecryptFinal_ex(ctx, *plain + *plain_len, &tmp_len) || tmp_len <= 0)
  {
    pelz_sgx_log(LOG_ERR, "key unwrap 'finalize' error ... exiting");
    free(*plain);
    *plain = NULL;
    *plain_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  *plain_len += (size_t)tmp_len;

  // verify that the resultant PT length matches the input CT length minus
  // the length of the 8-byte integrity check value
  if (*plain_len != cipher_data.cipher_len - 8)
  {
    pelz_sgx_log(LOG_ERR, "unwrapped data length mis-matches expected ... exiting");
    free(*plain);
    *plain = NULL;
    *plain_len = 0;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // now that the encryption is complete, clean-up cipher context
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}
