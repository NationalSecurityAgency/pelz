#include "charbuf.h"
#include "pelz_request_handler.h"
#include "pelz_log.h"
#include "common_table.h"
#include "key_table.h"
#include "aes_keywrap_3394nopad.h"

#include "sgx_trts.h"
#include "pelz_enclave_t.h"

RequestResponseStatus pelz_request_handler(RequestType request_type, charbuf key_id, charbuf data, charbuf * output)
{
  charbuf key;
  int index;

  if (table_lookup(KEY, key_id, &index))
  {
    if (key_table_add(key_id, &key))
    {
      pelz_log(LOG_ERR, "Key not added.");
      return KEK_LOAD_ERROR;
    }
  }
  else
  {
    key = new_charbuf(key_table.entries[index].value.key.len);
    if (key_table.entries[index].value.key.len != key.len)
    {
      pelz_log(LOG_ERR, "Charbuf creation error.");
      return CHARBUF_ERROR;
    }
    memcpy(key.chars, key_table.entries[index].value.key.chars, key.len);
  }

  //Encrypt or Decrypt data per request_type
  switch (request_type)
  {
  case REQ_ENC:
    if ((key.len < 16 || key.len % 8 != 0) || (data.len < 16 || data.len % 8 != 0))
    {
      secure_free_charbuf(&key);
      return KEY_OR_DATA_ERROR;
    }
    if (aes_keywrap_3394nopad_encrypt(key.chars, key.len, data.chars, data.len, &output->chars, &output->len))
    {
      secure_free_charbuf(&key);
      return ENCRYPT_ERROR;
    }
    break;
  case REQ_DEC:
    if ((key.len < 16 || key.len % 8 != 0) || (data.len < 24 || data.len % 8 != 0))
    {
      secure_free_charbuf(&key);
      return KEY_OR_DATA_ERROR;
    }
    if (aes_keywrap_3394nopad_decrypt(key.chars, key.len, data.chars, data.len, &output->chars, &output->len))
    {
      secure_free_charbuf(&key);
      return DECRYPT_ERROR;
    }
    break;
  default:
    secure_free_charbuf(&key);
    return REQUEST_TYPE_ERROR;

  }
  secure_free_charbuf(&key);
  return REQUEST_OK;
}
