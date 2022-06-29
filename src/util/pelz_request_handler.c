#include "charbuf.h"
#include "pelz_request_handler.h"
#include "common_table.h"
#include "aes_keywrap_3394nopad.h"

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

RequestResponseStatus pelz_encrypt_request_handler(RequestType request_type, charbuf key_id, charbuf plain_data, charbuf * cipher_data, charbuf* iv, charbuf* tag)
{
  charbuf cipher_data_internal;
  int index;

  if (table_lookup(KEY, key_id, &index))
  {
    return KEK_NOT_LOADED;
  }

  if ((key_table.entries[index].value.key.len < 16 || key_table.entries[index].value.key.len % 8 != 0) || (plain_data.len < 16 || plain_data.len % 8 != 0))
  {
    return KEY_OR_DATA_ERROR;
  }
  if (aes_keywrap_3394nopad_encrypt(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len,
				    plain_data.chars, plain_data.len, &cipher_data_internal.chars, &cipher_data_internal.len))
  {
    return ENCRYPT_ERROR;
  }
  
  cipher_data->len = cipher_data_internal.len;
  ocall_malloc(cipher_data->len, &cipher_data->chars);
  memcpy(cipher_data->chars, cipher_data_internal.chars, cipher_data->len);
  free_charbuf(&cipher_data_internal);
  return REQUEST_OK;
}


RequestResponseStatus pelz_decrypt_request_handler(RequestType request_type, charbuf key_id, charbuf cipher_data, charbuf iv, charbuf tag, charbuf * plain_data)
{
  charbuf plain_data_internal;
  int index;

  if (table_lookup(KEY, key_id, &index))
  {
    return KEK_NOT_LOADED;
  }

  if ((key_table.entries[index].value.key.len < 16 || key_table.entries[index].value.key.len % 8 != 0) || (cipher_data.len < 24 || cipher_data.len % 8 != 0))
  {
    return KEY_OR_DATA_ERROR;
  }
  if (aes_keywrap_3394nopad_decrypt(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len,
				    cipher_data.chars, cipher_data.len, &plain_data_internal.chars, &plain_data_internal.len))
  {
    return DECRYPT_ERROR;
  }
  
  plain_data->len = plain_data_internal.len;
  ocall_malloc(plain_data->len, &plain_data->chars);
  memcpy(plain_data->chars, plain_data_internal.chars, plain_data->len);
  free_charbuf(&plain_data_internal);
  return REQUEST_OK;
}
