#include "charbuf.h"
#include "pelz_request_handler.h"
#include "common_table.h"
#include "aes_keywrap_3394nopad.h"

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

RequestResponseStatus pelz_encrypt_request_handler(RequestType request_type, charbuf key_id, charbuf plain_data, charbuf * cipher_data, charbuf* iv, charbuf* tag)
{
  charbuf outData;
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
				    plain_data.chars, plain_data.len, &outData.chars, &outData.len))
  {
    return ENCRYPT_ERROR;
  }
  
  cipher_data->len = outData.len;
  ocall_malloc(cipher_data->len, &cipher_data->chars);
  memcpy(cipher_data->chars, outData.chars, cipher_data->len);
  return REQUEST_OK;
}


RequestResponseStatus pelz_decrypt_request_handler(RequestType request_type, charbuf key_id, charbuf data, charbuf iv, charbuf tag, charbuf * output)
{
  charbuf outData;
  int index;

  if (table_lookup(KEY, key_id, &index))
  {
    return KEK_NOT_LOADED;
  }

  if ((key_table.entries[index].value.key.len < 16 || key_table.entries[index].value.key.len % 8 != 0) || (data.len < 24 || data.len % 8 != 0))
  {
    return KEY_OR_DATA_ERROR;
  }
  if (aes_keywrap_3394nopad_decrypt(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len,
				    data.chars, data.len, &outData.chars, &outData.len))
  {
    return DECRYPT_ERROR;
  }
  
  output->len = outData.len;
  ocall_malloc(output->len, &output->chars);
  memcpy(output->chars, outData.chars, output->len);
  return REQUEST_OK;
}
