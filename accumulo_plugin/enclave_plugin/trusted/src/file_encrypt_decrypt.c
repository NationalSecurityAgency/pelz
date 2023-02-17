#include "charbuf.h"
#include "file_encrypt_decrpyt.h"
#include "cipher/pelz_cipher.h"
#include "pelz_enclave_log.h"

#include <openssl/rand.h>

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

charbuf key_gen(int key_size)
{
  if (key_size !> 0)
  {
    return NULL;
  }

  charbuf key = new_charbuf(key_size);
  if(RAND_priv_bytes(key.chars, key.len) != 1)
  {
    pelz_sgx_log(LOG_DEBUG, "Key generation failed");
    return NULL;
  }

  return key;
}

RequestResponseStatus file_encrypt_in_enclave(charbuf plain_data, charbuf cipher_name, charbuf * cipher_data, charbuf * key, charbuf * iv, charbuf * tag)
{
  pelz_sgx_log(LOG_DEBUG, "File Encryption");
  key_size = 32;
  charbuf temp_key = key_gen(key_size);
  if (temp_key == NULL)
  {
    return ENCRYPT_ERROR;
  }
  key->len = temp_key.len;
  ocall_malloc(key->len, &key->chars);
  memcpy(key->chars, temp_key.chars, key->len);

  unsigned char* cipher_name_string = null_terminated_string_from_charbuf(cipher_name);
  if(cipher_name_string == NULL)
  {
    pelz_sgx_log(LOG_DEBUG, "Cipher name string missing");
    return ENCRYPT_ERROR;
  }

  cipher_t cipher_struct = pelz_get_cipher_t_from_string((char*)cipher_name_string);

  if(cipher_struct.cipher_name == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Cipher Name in struct missing");
    return ENCRYPT_ERROR;
  }

  pelz_sgx_log(LOG_DEBUG, "Cipher Encrypt");
  cipher_data_t cipher_data_st;
  if (cipher_struct.encrypt_fn(key->chars,
             key->len,
             plain_data.chars,
             plain_data.len,
             &cipher_data_st))
  {
    free(cipher_data_st.cipher);
    free(cipher_data_st.iv);
    free(cipher_data_st.tag);
    pelz_sgx_log(LOG_ERR, "Encrypt Error");
    return ENCRYPT_ERROR;
  }

  // Set up the output for cipher_data_st.cipher first because it's the only
  // one that should always be present and it makes the error handling slightly
  // cleaner to do it first.
  if(cipher_data_st.cipher_len > 0 && cipher_data_st.cipher != NULL)
  {
    ocall_malloc(cipher_data_st.cipher_len, &cipher_data->chars);
    if(cipher_data->chars == NULL)
    {
      free(cipher_data_st.cipher);
      free(cipher_data_st.tag);
      free(cipher_data_st.iv);

      cipher_data->len = 0;
      pelz_sgx_log(LOG_ERR, "Cipher data allocation error");
      return ENCRYPT_ERROR;
    }
    cipher_data->len = cipher_data_st.cipher_len;
    memcpy(cipher_data->chars, cipher_data_st.cipher, cipher_data->len);
  }
  else
  {
    free(cipher_data_st.cipher);
    free(cipher_data_st.tag);
    free(cipher_data_st.iv);
    pelz_sgx_log(LOG_ERR, "Cipher data missing");
    return ENCRYPT_ERROR;
  }
  free(cipher_data_st.cipher);

  if(cipher_data_st.iv_len > 0 && cipher_data_st.iv != NULL)
  {
    ocall_malloc(cipher_data_st.iv_len, &iv->chars);
    if(iv->chars == NULL)
    {
      ocall_free(cipher_data->chars, cipher_data->len);
      cipher_data->chars = NULL;
      cipher_data->len = 0;

      iv->len = 0;

      free(cipher_data_st.iv);
      free(cipher_data_st.tag);
      pelz_sgx_log(LOG_ERR, "IV alloctation error");
      return ENCRYPT_ERROR;
    }
    iv->len = cipher_data_st.iv_len;
    memcpy(iv->chars, cipher_data_st.iv, iv->len);
  }
  free(cipher_data_st.iv);

  if(cipher_data_st.tag_len > 0 && cipher_data_st.tag != NULL)
  {
    ocall_malloc(cipher_data_st.tag_len, &tag->chars);
    if(tag->chars == NULL)
    {
      ocall_free(cipher_data->chars, cipher_data->len);
      cipher_data->chars = NULL;
      cipher_data->len = 0;

      ocall_free(iv->chars, iv->len);
      iv->chars = NULL;
      iv->len = 0;

      tag->len = 0;

      free(cipher_data_st.tag);
      pelz_sgx_log(LOG_ERR, "Tag allocation error");
      return ENCRYPT_ERROR;
    }
    tag->len = cipher_data_st.tag_len;
    memcpy(tag->chars, cipher_data_st.tag, tag->len);
  }
  free(cipher_data_st.tag);
  pelz_sgx_log(LOG_DEBUG, "Encrypt Request Handler Successful");
  return REQUEST_OK;
}

RequestResponseStatus file_decrypt_in_enclave(charbuf cipher_name, charbuf cipher_data, charbuf key, charbuf iv, charbuf tag, charbuf * plain_data)
{
  pelz_sgx_log(LOG_DEBUG, "File Decryption");
  charbuf plain_data_internal;

  unsigned char* cipher_name_string = null_terminated_string_from_charbuf(cipher_name);
  if(cipher_name_string == NULL)
  {
    pelz_sgx_log(LOG_DEBUG, "Cipher name string missing");
    return DECRYPT_ERROR;
  }

  cipher_t cipher_struct = pelz_get_cipher_t_from_string((char*)cipher_name_string);

  if(cipher_struct.cipher_name == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Cipher Name in struct missing");
    return DECRYPT_ERROR;
  }

  cipher_data_t cipher_data_st;
  cipher_data_st.cipher = cipher_data.chars;
  cipher_data_st.cipher_len = cipher_data.len;
  cipher_data_st.iv = iv.chars;
  cipher_data_st.iv_len = iv.len;
  cipher_data_st.tag = tag.chars;
  cipher_data_st.tag_len = tag.len;

  pelz_sgx_log(LOG_DEBUG, "Cipher Decrypt");
  if(cipher_struct.decrypt_fn(key.chars,
            key.len,
            cipher_data_st,
            &plain_data_internal.chars,
            &plain_data_internal.len))
  {
    pelz_sgx_log(LOG_DEBUG, "Decrypt Error");
    return DECRYPT_ERROR;
  }

  plain_data->len = plain_data_internal.len;
  ocall_malloc(plain_data->len, &plain_data->chars);
  if(plain_data->chars == NULL)
  {
    plain_data->len = 0;
    free_charbuf(&plain_data_internal);
    pelz_sgx_log(LOG_ERR, "Plaintext buffer allocation failed");
    return DECRYPT_ERROR;
  }
  memcpy(plain_data->chars, plain_data_internal.chars, plain_data->len);
  free_charbuf(&plain_data_internal);
  pelz_sgx_log(LOG_DEBUG, "File Decryption Successful");
  return REQUEST_OK;
}
