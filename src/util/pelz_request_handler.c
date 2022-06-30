#include "charbuf.h"
#include "pelz_request_handler.h"
#include "common_table.h"
#include "cipher/pelz_cipher.h"

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

RequestResponseStatus pelz_encrypt_request_handler(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf plain_data, charbuf * cipher_data, charbuf* iv, charbuf* tag)
{
  charbuf cipher_data_internal;
  int index;

  unsigned char* cipher_name_string = null_terminated_string_from_charbuf(cipher_name);
  if(cipher_name_string == NULL)
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
			       &iv->chars,
			       &iv->len,
			       &cipher_data_internal.chars,
			       &cipher_data_internal.len,
			       &tag->chars,
			       &tag->len))
  {
    return ENCRYPT_ERROR;
  }
  
  cipher_data->len = cipher_data_internal.len;
  ocall_malloc(cipher_data->len, &cipher_data->chars);
  if(cipher_data->chars == NULL)
  {
    free_charbuf(&cipher_data_internal);
    return ENCRYPT_ERROR;
  }
  memcpy(cipher_data->chars, cipher_data_internal.chars, cipher_data->len);
  free_charbuf(&cipher_data_internal);
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
    free_charbuf(&plain_data_internal);
    return DECRYPT_ERROR;
  }
  memcpy(plain_data->chars, plain_data_internal.chars, plain_data->len);
  free_charbuf(&plain_data_internal);
  return REQUEST_OK;
}
