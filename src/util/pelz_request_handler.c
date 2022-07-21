#include "charbuf.h"
#include "pelz_request_handler.h"
#include "common_table.h"
#include "cipher/pelz_cipher.h"

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

RequestResponseStatus pelz_encrypt_request_handler(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf plain_data, charbuf * cipher_data, charbuf* iv, charbuf* tag)
{
  int index;

  unsigned char* cipher_name_string = null_terminated_string_from_charbuf(cipher_name);
  if(cipher_name_string == NULL)
  {
    return ENCRYPT_ERROR;
  }

  if(key_id.chars == NULL || key_id.len == 0)
  {
    return ENCRYPT_ERROR;
  }
  
  cipher_t cipher_struct = pelz_get_cipher_t_from_string((char*)cipher_name_string);
  free(cipher_name_string);

  if(cipher_struct.cipher_name == NULL)
  {
    return ENCRYPT_ERROR;
  }
  
  if (table_lookup(KEY, key_id, &index))
  {
    return KEK_NOT_LOADED;
  }

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
      return ENCRYPT_ERROR;
    }
    tag->len = cipher_data_st.tag_len;
    memcpy(tag->chars, cipher_data_st.tag, tag->len);
  }
  free(cipher_data_st.tag);
  return REQUEST_OK;
}


RequestResponseStatus pelz_decrypt_request_handler(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf cipher_data, charbuf iv, charbuf tag, charbuf * plain_data)
{
  charbuf plain_data_internal;
  int index;

  unsigned char* cipher_name_string = null_terminated_string_from_charbuf(cipher_name);
  if(cipher_name_string == NULL)
  {
    return DECRYPT_ERROR;
  }

  if(key_id.chars == NULL || key_id.len == 0)
  {
    return DECRYPT_ERROR;
  }
  
  cipher_t cipher_struct = pelz_get_cipher_t_from_string((char*)cipher_name_string);
  free(cipher_name_string);

  if(cipher_struct.cipher_name == NULL)
  {
    return DECRYPT_ERROR;
  }
  if (table_lookup(KEY, key_id, &index))
  {
    return KEK_NOT_LOADED;
  }

  cipher_data_t cipher_data_st;
  cipher_data_st.cipher = cipher_data.chars;
  cipher_data_st.cipher_len = cipher_data.len;
  cipher_data_st.iv = iv.chars;
  cipher_data_st.iv_len = iv.len;
  cipher_data_st.tag = tag.chars;
  cipher_data_st.tag_len = tag.len;
  
  if(cipher_struct.decrypt_fn(key_table.entries[index].value.key.chars,
			      key_table.entries[index].value.key.len,
			      cipher_data_st,
			      &plain_data_internal.chars,
			      &plain_data_internal.len))
  {
    return DECRYPT_ERROR;
  }
  
  plain_data->len = plain_data_internal.len;
  ocall_malloc(plain_data->len, &plain_data->chars);
  if(plain_data->chars == NULL)
  {
    plain_data->len = 0;
    free_charbuf(&plain_data_internal);
    return DECRYPT_ERROR;
  }
  memcpy(plain_data->chars, plain_data_internal.chars, plain_data->len);
  free_charbuf(&plain_data_internal);
  return REQUEST_OK;
}
