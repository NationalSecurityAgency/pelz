#include "charbuf.h"
#include "pelz_request_handler.h"
#include "pelz_log.h"
#include "common_table.h"
#include "aes_keywrap_3394nopad.h"

#include "sgx_trts.h"
#include "pelz_enclave_t.h"

RequestResponseStatus pelz_request_handler(RequestType request_type, charbuf key_id, charbuf data, charbuf * output)
{
  int index;
  int ret;

  if (table_lookup(KEY, key_id, &index))
  {
    key_load(&ret, key_id);
    if (ret == 1)
    {
      pelz_log(LOG_ERR, "Key not added.");
      return KEK_LOAD_ERROR;
    }
    index = key_table.num_entries - 1;
    if (cmp_charbuf(key_table.entries[index].id, key_id) != 0)
    {
      return KEK_LOAD_ERROR;
    }
  }

  //Encrypt or Decrypt data per request_type
  switch (request_type)
  {
  case REQ_ENC:
    if ((key_table.entries[index].value.key.len < 16 || key_table.entries[index].value.key.len % 8 != 0) || (data.len < 16
        || data.len % 8 != 0))
    {
      return KEY_OR_DATA_ERROR;
    }
    if (aes_keywrap_3394nopad_encrypt(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len,
        data.chars, data.len, &output->chars, &output->len))
    {
      return ENCRYPT_ERROR;
    }
    break;
  case REQ_DEC:
    if ((key_table.entries[index].value.key.len < 16 || key_table.entries[index].value.key.len % 8 != 0) || (data.len < 24
        || data.len % 8 != 0))
    {
      return KEY_OR_DATA_ERROR;
    }
    if (aes_keywrap_3394nopad_decrypt(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len,
        data.chars, data.len, &output->chars, &output->len))
    {
      return DECRYPT_ERROR;
    }
    break;
  default:
    return REQUEST_TYPE_ERROR;

  }
  return REQUEST_OK;
}
