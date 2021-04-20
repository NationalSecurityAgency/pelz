#include <stdio.h>
#include <stdlib.h>

#include "CharBuf.h"
#include "pelz_log.h"
#include "pelz_request_handler.h"
#include "key_table.h"
#include "aes_keywrap_3394nopad.h"
#include "key_table.h"
#include "pelz_io.h"

//Function to test socket code with working encryption code
RequestResponseStatus pelz_request_handler(RequestType request_type, CharBuf key_id, CharBuf data, CharBuf output)
{
  CharBuf key;

  if (key_table_lookup(key_id, &key))
  {
    if (key_table_add(key_id, &key))
    {
      pelz_log(LOG_ERR, "Key not added.");
      return KEK_LOAD_ERROR;
    }
  }

  //Encrypt or Decrypt data per request_type
  switch (request_type)
  {
  case REQ_ENC:
    if ((key.len < 16 || key.len % 8 != 0) && (data.len < 16 || data.len % 8 != 0))
    {
      secureFreeCharBuf(&key);
      return KEY_OR_DATA_ERROR;
    }
    if (aes_keywrap_3394nopad_encrypt(key.chars, key.len, data.chars, data.len, &output.chars, &output.len))
    {
      secureFreeCharBuf(&key);
      return ENCRYPT_ERROR;
    }
    break;
  case REQ_DEC:
    if (aes_keywrap_3394nopad_decrypt(key.chars, key.len, data.chars, data.len, &output.chars, &output.len))
    {
      secureFreeCharBuf(&key);
      return DECRYPT_ERROR;
    }
    break;
  default:
    secureFreeCharBuf(&key);
    return REQUEST_TYPE_ERROR;

  }
  secureFreeCharBuf(&key);
  return REQUEST_OK;
}
