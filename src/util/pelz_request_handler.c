#include "charbuf.h"
#include "pelz_request_handler.h"
#include "common_table.h"
#include "cipher/pelz_cipher.h"
#include "pelz_enclave_log.h"
#include "enclave_request_signing.h"

#include <openssl/rand.h>

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED


RequestResponseStatus pelz_encrypt_request_handler(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf plain_data, charbuf * cipher_data, charbuf* iv, charbuf* tag, charbuf signature, charbuf cert)
{
  pelz_sgx_log(LOG_DEBUG, "Encrypt Request Handler");
  // Start by checking that the signature validates, if present (and required).
  if(request_type == REQ_ENC_SIGNED)
  {
    if(validate_signature(request_type, key_id, cipher_name, plain_data, *iv, *tag, signature, cert) == 1)
    {
      pelz_sgx_log(LOG_ERR, "Validate Signature failure");
      return SIGNATURE_ERROR;
    }
  }
  size_t index;
  
  unsigned char* cipher_name_string = null_terminated_string_from_charbuf(cipher_name);
  if(cipher_name_string == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Cipher name string missing");
    return ENCRYPT_ERROR;
  }

  if(key_id.chars == NULL || key_id.len == 0)
  {
    pelz_sgx_log(LOG_ERR, "Key ID missing");
    return ENCRYPT_ERROR;
  }
  
  cipher_t cipher_struct = pelz_get_cipher_t_from_string((char*)cipher_name_string);
  free(cipher_name_string);

  if(cipher_struct.cipher_name == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Cipher Name in struct missing");
    return ENCRYPT_ERROR;
  }
  
  pelz_sgx_log(LOG_DEBUG, "KEK Load Check");
  if (table_lookup(KEY, key_id, &index))
  {
    pelz_sgx_log(LOG_ERR, "KEK not loaded");
    return KEK_NOT_LOADED;
  }

  pelz_sgx_log(LOG_DEBUG, "Cipher Encrypt");
  cipher_data_t cipher_data_st;
  if (cipher_struct.encrypt_fn(key_table.entries[index].value.key.chars,
			       key_table.entries[index].value.key.len,
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
      pelz_sgx_log(LOG_ERR, "IV allocation error");
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


RequestResponseStatus pelz_decrypt_request_handler(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf cipher_data, charbuf iv, charbuf tag, charbuf * plain_data, charbuf signature, charbuf cert)
{
  pelz_sgx_log(LOG_DEBUG, "Decrypt Request Handler");
  // Start by checking that the signature validates, if present (and required).
  if(request_type == REQ_DEC_SIGNED)
  {
    if(validate_signature(request_type, key_id, cipher_name, cipher_data, iv, tag, signature, cert) == 1)
    {
      pelz_sgx_log(LOG_ERR, "Validate Signature failure");
      return SIGNATURE_ERROR;
    }
  }
  
  charbuf plain_data_internal;
  size_t index;

  unsigned char* cipher_name_string = null_terminated_string_from_charbuf(cipher_name);
  if(cipher_name_string == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Cipher name string missing");
    return DECRYPT_ERROR;
  }

  if(key_id.chars == NULL || key_id.len == 0)
  {
    pelz_sgx_log(LOG_ERR, "Key ID missing");
    return DECRYPT_ERROR;
  }
  
  cipher_t cipher_struct = pelz_get_cipher_t_from_string((char*)cipher_name_string);
  free(cipher_name_string);

  if(cipher_struct.cipher_name == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Cipher Name in struct missing");
    return DECRYPT_ERROR;
  }

  pelz_sgx_log(LOG_DEBUG, "KEK Load Check");
  if (table_lookup(KEY, key_id, &index))
  {
    pelz_sgx_log(LOG_ERR, "KEK not loaded");
    return KEK_NOT_LOADED;
  }

  cipher_data_t cipher_data_st;
  cipher_data_st.cipher = cipher_data.chars;
  cipher_data_st.cipher_len = cipher_data.len;
  cipher_data_st.iv = iv.chars;
  cipher_data_st.iv_len = iv.len;
  cipher_data_st.tag = tag.chars;
  cipher_data_st.tag_len = tag.len;

  pelz_sgx_log(LOG_DEBUG, "Cipher Decrypt");
  if(cipher_struct.decrypt_fn(key_table.entries[index].value.key.chars,
			      key_table.entries[index].value.key.len,
			      cipher_data_st,
			      &plain_data_internal.chars,
			      &plain_data_internal.len))
  {
    pelz_sgx_log(LOG_ERR, "Decrypt Error");
    return DECRYPT_ERROR;
  }
  
  plain_data->len = plain_data_internal.len;
  ocall_malloc(plain_data->len, &plain_data->chars);
  if(plain_data->chars == NULL)
  {
    plain_data->len = 0;
    free_charbuf(&plain_data_internal);
    pelz_sgx_log(LOG_ERR, "Plain data missing");
    return DECRYPT_ERROR;
  }
  memcpy(plain_data->chars, plain_data_internal.chars, plain_data->len);
  free_charbuf(&plain_data_internal);
  pelz_sgx_log(LOG_DEBUG, "Decrypt Request Handler Successful");
  return REQUEST_OK;
}
