#include "charbuf.h"
#include "pelz_request_handler.h"
#include "common_table.h"
#include "cipher/pelz_cipher.h"

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

RequestResponseStatus pelz_encrypt_request_handler(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf plain_data, charbuf * cipher_data, charbuf* iv, charbuf* tag)
{
  charbuf cipher_data_internal;
  charbuf iv_internal = new_charbuf(0);
  charbuf tag_internal = new_charbuf(0);
  
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

  if (cipher_struct.encrypt_fn(key_table.entries[index].value.key.chars,
			       key_table.entries[index].value.key.len,
			       plain_data.chars,
			       plain_data.len,
			       &iv_internal.chars,
			       &iv_internal.len,
			       &cipher_data_internal.chars,
			       &cipher_data_internal.len,
			       &tag_internal.chars,
			       &tag_internal.len))
  {
    return ENCRYPT_ERROR;
  }

  iv->len = iv_internal.len;
  if(iv->len > 0)
  {
    ocall_malloc(iv->len, &iv->chars);
    if(iv->chars == NULL)
    {
      free_charbuf(&cipher_data_internal);
      free_charbuf(&iv_internal);
      free_charbuf(&tag_internal);
      iv->len = 0;
      tag->len = 0;
      cipher_data->len = 0;
      return ENCRYPT_ERROR;
    }
    memcpy(iv->chars, iv_internal.chars, iv->len);
  }

  tag->len = tag_internal.len;
  if(tag->len > 0)
  {
    ocall_malloc(tag->len, &tag->chars);
    if(tag->chars == NULL)
    {
      free_charbuf(&cipher_data_internal);
      free_charbuf(&iv_internal);
      free_charbuf(&tag_internal);
      tag->len = 0;
      cipher_data->len = 0;
      if(iv->chars != NULL)
      {
	ocall_free(iv->chars, iv->len);
	iv->chars = NULL;
	iv->len = 0;
      }
      return ENCRYPT_ERROR;
    }
    memcpy(tag->chars, tag_internal.chars, tag->len);
  }
  
  cipher_data->len = cipher_data_internal.len;
  ocall_malloc(cipher_data->len, &cipher_data->chars);
  if(cipher_data->chars == NULL)
  {
    free_charbuf(&cipher_data_internal);
    free_charbuf(&iv_internal);
    free_charbuf(&tag_internal);
    if(iv->chars != NULL)
    {
      ocall_free(iv->chars, iv->len);
      iv->chars = NULL;
      iv->len = 0;
    }
    if(tag->chars != NULL)
    {
      ocall_free(tag->chars, tag->len);
      tag->chars = NULL;
      tag->len = 0;
    }
    cipher_data->len = 0;
    return ENCRYPT_ERROR;
  }
  memcpy(cipher_data->chars, cipher_data_internal.chars, cipher_data->len);
  free_charbuf(&cipher_data_internal);
  free_charbuf(&iv_internal);
  free_charbuf(&tag_internal);
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

  if(cipher_struct.decrypt_fn(key_table.entries[index].value.key.chars,
			      key_table.entries[index].value.key.len,
			      iv.chars,
			      iv.len,
			      cipher_data.chars,
			      cipher_data.len,
			      tag.chars,
			      tag.len,
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
