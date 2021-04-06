/*
 * pelz_key_service.c
 */
#include <pelz_service.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#include <aes_keywrap_3394nopad.h>
#include <pelz_socket.h>
#include <pelz_json_parser.h>
#include <pelz_request_handler.h>
#include <key_table.h>
#include <util.h>
#include <CharBuf.h>
#include <pelz_log.h>

//Function to test socket code with working encryption code
int pelz_key_service(CharBuf request, CharBuf * message, KeyTable * key_table, int socket_id)
{
  //Initializing Variables
  RequestValues request_values;

  CharBuf key;
  CharBuf data;
  CharBuf output;
  char *err_message;

  request_values.request_type = 0;

  //Parse request for processing
  if (request_decoder(request, &request_values))
  {
    err_message = "Missing Data";
    error_message_encoder(message, err_message);
    pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message->chars, (int) message->len);
    freeCharBuf(&request);
    return (1);
  }

  freeCharBuf(&request);
  if (key_table_lookup(request_values.key_id, &key, key_table, false))
  {
    if (key_table_add(request_values.key_id, &key, key_table))
    {
      pelz_log(LOG_ERR, "Key not added.");
      err_message = "Key not added";
      error_message_encoder(message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message->chars, (int) message->len);
      freeCharBuf(&request);
      return (1);
    }
  }

  pelz_log(LOG_DEBUG, "%d::Completed request decode.", socket_id);
  //Encrypt or Decrypt data per request_type
  switch (request_values.request_type)
  {
  case REQ_ENC:
    pelz_log(LOG_DEBUG, "%d::Encryption Request Start", socket_id);
    decodeBase64Data(request_values.data_in.chars, request_values.data_in.len, &data.chars, &data.len);
    freeCharBuf(&request_values.data_in);
    pelz_log(LOG_DEBUG, "%d::Base64Decode Complete", socket_id);
    if ((key.len < 16 || key.len % 8 != 0) && (data.len < 16 || data.len % 8 != 0))
    {
      err_message = "Key or Data Error";
      freeCharBuf(&data);
      secureFreeCharBuf(&key);
      error_message_encoder(message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message->chars, (int) message->len);
      return (1);
    }
    if (aes_keywrap_3394nopad_encrypt(key.chars, key.len, data.chars, data.len, &output.chars, &output.len))
    {
      err_message = "Encrypt Error";
      freeCharBuf(&data);
      secureFreeCharBuf(&key);
      error_message_encoder(message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message->chars, (int) message->len);
      return (1);
    }
    pelz_log(LOG_DEBUG, "%d::Encrypt Wrapper Complete", socket_id);
    freeCharBuf(&data);
    encodeBase64Data(output.chars, output.len, &request_values.data_out.chars, &request_values.data_out.len);
    if (strlen((char *) request_values.data_out.chars) != request_values.data_out.len)
      request_values.data_out.chars[request_values.data_out.len] = 0;
    pelz_log(LOG_DEBUG, "%d::Base64Encode Complete", socket_id);
    break;
  case REQ_DEC:
    pelz_log(LOG_DEBUG, "%d::Decryption Request Start", socket_id);
    decodeBase64Data(request_values.data_in.chars, request_values.data_in.len, &data.chars, &data.len);
    freeCharBuf(&request_values.data_in);
    pelz_log(LOG_DEBUG, "%d::Base64Decode Complete", socket_id);
    if (aes_keywrap_3394nopad_decrypt(key.chars, key.len, data.chars, data.len, &output.chars, &output.len))
    {
      err_message = "Decrypt Error";
      freeCharBuf(&data);
      secureFreeCharBuf(&key);
      error_message_encoder(message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message->chars, (int) message->len);
      return (1);
    }
    pelz_log(LOG_DEBUG, "%d::Decrypt Wrapper Complete", socket_id);
    freeCharBuf(&data);
    encodeBase64Data(output.chars, output.len, &request_values.data_out.chars, &request_values.data_out.len);
    if (strlen((char *) request_values.data_out.chars) != request_values.data_out.len)
      request_values.data_out.chars[request_values.data_out.len] = 0;
    pelz_log(LOG_DEBUG, "%d::Base64Encode Complete", socket_id);
    break;
  default:
    err_message = "Request Type Error";
    error_message_encoder(message, err_message);
    freeCharBuf(&request_values.key_id);
    freeCharBuf(&request_values.data_in);
    pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message->chars, (int) message->len);
    return (1);

  }

  //Send processed request back to client
  message_encoder(request_values, message);
  pelz_log(LOG_DEBUG, "%d::Message Encode Complete", socket_id);
  pelz_log(LOG_DEBUG, "%d::Message: %s, %d", socket_id, message->chars, (int) message->len);
  freeCharBuf(&request_values.key_id);
  freeCharBuf(&request_values.data_out);
  secureFreeCharBuf(&key);
  freeCharBuf(&output);
  return (0);
}
