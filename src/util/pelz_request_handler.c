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
int pelz_request_handler(RequestType request_type, CharBuf key_id, CharBuf data, CharBuf output, CharBuf * message,
  int socket_id)
{
  //  char *err_message;
  CharBuf key;

  if (key_table_lookup(key_id, &key))
  {
    if (key_table_add(key_id, &key))
    {
      pelz_log(LOG_ERR, "Key not added.");
      //      err_message = "Key not added";
      //      error_message_encoder(message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message->chars, (int) message->len);
      return (1);
    }
  }

  pelz_log(LOG_DEBUG, "%d::Completed request decode.", socket_id);
  //Encrypt or Decrypt data per request_type
  switch (request_type)
  {
  case REQ_ENC:
    if ((key.len < 16 || key.len % 8 != 0) && (data.len < 16 || data.len % 8 != 0))
    {
      //      err_message = "Key or Data Error";
      secureFreeCharBuf(&key);
      //      error_message_encoder(message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message->chars, (int) message->len);
      return (1);
    }
    if (aes_keywrap_3394nopad_encrypt(key.chars, key.len, data.chars, data.len, &output.chars, &output.len))
    {
      //      err_message = "Encrypt Error";
      freeCharBuf(&data);
      secureFreeCharBuf(&key);
      //      error_message_encoder(message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message->chars, (int) message->len);
      return (1);
    }
    pelz_log(LOG_DEBUG, "%d::Encrypt Wrapper Complete", socket_id);
    break;
  case REQ_DEC:
    if (aes_keywrap_3394nopad_decrypt(key.chars, key.len, data.chars, data.len, &output.chars, &output.len))
    {
      //      err_message = "Decrypt Error";
      secureFreeCharBuf(&key);
      //      error_message_encoder(message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message->chars, (int) message->len);
      return (1);
    }
    pelz_log(LOG_DEBUG, "%d::Decrypt Wrapper Complete", socket_id);
    break;
  default:
    //    err_message = "Request Type Error";
    //    error_message_encoder(message, err_message);
    pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message->chars, (int) message->len);
    secureFreeCharBuf(&key);
    return (1);

  }
  secureFreeCharBuf(&key);
  return (0);
}
