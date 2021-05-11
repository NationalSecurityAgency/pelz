/*
 * json_parser.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cjson/cJSON.h>

#include <pelz_json_parser.h>
#include <pelz_request_handler.h>
#include <CharBuf.h>
#include <pelz_log.h>

int request_decoder(CharBuf request, RequestType * request_type, CharBuf * key_id, CharBuf * data)
{
  cJSON *json;
  char *str = NULL;

  str = calloc((request.len + 1), sizeof(char));
  memcpy(str, request.chars, request.len);
  json = cJSON_Parse(str);
  free(str);
  if (!cJSON_HasObjectItem(json, "request_type"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: request_type.");
    cJSON_Delete(json);
    return (1);
  }
  else if (!cJSON_IsNumber(cJSON_GetObjectItem(json, "request_type")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: request_type. Data type should be integer.");
    cJSON_Delete(json);
    return (1);
  }
  *request_type = cJSON_GetObjectItemCaseSensitive(json, "request_type")->valueint;
  switch (*request_type)
  {
  case REQ_ENC:
    if (encrypt_parser(json, key_id, data))
    {
      pelz_log(LOG_ERR, "Encrypt Request Parser Error");
      cJSON_Delete(json);
      return (1);
    }
    break;
  case REQ_DEC:
    if (decrypt_parser(json, key_id, data))
    {
      pelz_log(LOG_ERR, "Decrypt Request Parser Error");
      cJSON_Delete(json);
      return (1);
    }
    break;
  default:
    pelz_log(LOG_WARNING, "Invalid Request Type");
    cJSON_Delete(json);
    return (1);
  }
  cJSON_Delete(json);
  return (0);
}

int error_message_encoder(CharBuf * message, char *err_message)
{
  cJSON *root;
  char *tmp = NULL;

  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "error", cJSON_CreateString(err_message));
  if (cJSON_IsInvalid(root))
  {
    pelz_log(LOG_ERR, "JSON Message Creation Failed");
    cJSON_Delete(root);
    return (1);
  }
  tmp = cJSON_PrintUnformatted(root);
  *message = newCharBuf(strlen(tmp));
  memcpy(message->chars, tmp, message->len);
  cJSON_Delete(root);
  free(tmp);
  return (0);
}

int message_encoder(RequestType request_type, CharBuf key_id, CharBuf data, CharBuf * message)
{
  cJSON *root;
  char *tmp = NULL;

  root = cJSON_CreateObject();
  switch (request_type)
  {
  case REQ_ENC:
    tmp = calloc((key_id.len + 1), sizeof(char));
    memcpy(tmp, key_id.chars, key_id.len);
    cJSON_AddItemToObject(root, "key_id", cJSON_CreateString(tmp));
    free(tmp);
    cJSON_AddItemToObject(root, "key_id_len", cJSON_CreateNumber(key_id.len));
    tmp = calloc((data.len + 1), sizeof(char));
    memcpy(tmp, data.chars, data.len);
    cJSON_AddItemToObject(root, "enc_out", cJSON_CreateString(tmp));
    free(tmp);
    cJSON_AddItemToObject(root, "enc_out_len", cJSON_CreateNumber(data.len));
    break;
  case REQ_DEC:
    tmp = calloc((key_id.len + 1), sizeof(char));
    memcpy(tmp, key_id.chars, key_id.len);
    cJSON_AddItemToObject(root, "key_id", cJSON_CreateString(tmp));
    free(tmp);
    cJSON_AddItemToObject(root, "key_id_len", cJSON_CreateNumber(key_id.len));
    tmp = calloc((data.len + 1), sizeof(char));
    memcpy(tmp, data.chars, data.len);
    cJSON_AddItemToObject(root, "dec_out", cJSON_CreateString(tmp));
    free(tmp);
    cJSON_AddItemToObject(root, "dec_out_len", cJSON_CreateNumber(data.len));
    break;
  default:
    pelz_log(LOG_ERR, "Request Type not recognized.");
    cJSON_Delete(root);
    return (1);
  }
  if (cJSON_IsInvalid(root))
  {
    pelz_log(LOG_ERR, "JSON Message Creation Failed");
    cJSON_Delete(root);
    return (1);
  }
  tmp = cJSON_PrintUnformatted(root);
  *message = newCharBuf(strlen(tmp));
  memcpy(message->chars, tmp, message->len);
  cJSON_Delete(root);
  free(tmp);
  return (0);
}

int encrypt_parser(cJSON * json, CharBuf * key_id, CharBuf * data)
{
  if (!cJSON_HasObjectItem(json, "key_id"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: key_id.");
    return (1);
  }
  else if (!cJSON_HasObjectItem(json, "key_id_len"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: key_id_len.");
    return (1);
  }
  else if (!cJSON_HasObjectItem(json, "enc_data"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: enc_data.");
    return (1);
  }
  else if (!cJSON_HasObjectItem(json, "enc_data_len"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: enc_data_len.");
    return (1);
  }
  if (!cJSON_IsNumber(cJSON_GetObjectItem(json, "key_id_len")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: key_id_len. Data type should be integer.");
    return (1);
  }
  *key_id = newCharBuf(cJSON_GetObjectItemCaseSensitive(json, "key_id_len")->valueint);
  if (!cJSON_IsString(cJSON_GetObjectItem(json, "key_id")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: key_id. Data type should be string.");
    freeCharBuf(key_id);
    return (1);
  }
  if (cJSON_GetObjectItemCaseSensitive(json, "key_id")->valuestring != NULL)
  {
    if (strlen(cJSON_GetObjectItemCaseSensitive(json, "key_id")->valuestring) != key_id->len)
    {
      pelz_log(LOG_ERR, "Length of value in JSON key: key_id does not match value in JSON key: key_id_len.");
      freeCharBuf(key_id);
      return (1);
    }
    memcpy(key_id->chars, cJSON_GetObjectItemCaseSensitive(json, "key_id")->valuestring, key_id->len);
  }
  else
  {
    pelz_log(LOG_ERR, "No value in JSON key: key_id.");
    freeCharBuf(key_id);
    return (1);
  }
  if (!cJSON_IsNumber(cJSON_GetObjectItem(json, "enc_data_len")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: enc_data_len. Data type should be integer.");
    freeCharBuf(key_id);
    return (1);
  }
  *data = newCharBuf(cJSON_GetObjectItemCaseSensitive(json, "enc_data_len")->valueint);
  if (!cJSON_IsString(cJSON_GetObjectItem(json, "enc_data")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: enc_data. Data type should be string.");
    freeCharBuf(key_id);
    freeCharBuf(data);
    return (1);
  }
  if (cJSON_GetObjectItemCaseSensitive(json, "enc_data")->valuestring != NULL)
  {
    if (strlen(cJSON_GetObjectItemCaseSensitive(json, "enc_data")->valuestring) != data->len)
    {
      pelz_log(LOG_ERR, "Length of value in JSON key: enc_data does not match value in JSON key: enc_data_len.");
      freeCharBuf(key_id);
      freeCharBuf(data);
      return (1);
    }
    memcpy(data->chars, cJSON_GetObjectItemCaseSensitive(json, "enc_data")->valuestring, data->len);
  }
  else
  {
    pelz_log(LOG_ERR, "No value in JSON key: enc_data.");
    freeCharBuf(key_id);
    freeCharBuf(data);
    return (1);
  }
  return (0);
}

int decrypt_parser(cJSON * json, CharBuf * key_id, CharBuf * data)
{
  if (!cJSON_HasObjectItem(json, "key_id"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: key_id.");
    return (1);
  }
  else if (!cJSON_HasObjectItem(json, "key_id_len"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: key_id_len.");
    return (1);
  }
  else if (!cJSON_HasObjectItem(json, "dec_data"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: dec_data.");
    return (1);
  }
  else if (!cJSON_HasObjectItem(json, "dec_data_len"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: dec_data_len.");
    return (1);
  }
  if (!cJSON_IsNumber(cJSON_GetObjectItem(json, "key_id_len")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: key_id_len. Data type should be integer.");
    return (1);
  }
  *key_id = newCharBuf(cJSON_GetObjectItemCaseSensitive(json, "key_id_len")->valueint);
  if (!cJSON_IsString(cJSON_GetObjectItem(json, "key_id")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: key_id. Data type should be string.");
    freeCharBuf(key_id);
    return (1);
  }
  if (cJSON_GetObjectItemCaseSensitive(json, "key_id")->valuestring != NULL)
  {
    if (strlen(cJSON_GetObjectItemCaseSensitive(json, "key_id")->valuestring) != key_id->len)
    {
      pelz_log(LOG_ERR, "Length of value in JSON key: key_id does not match value in JSON key: key_id_len.");
      freeCharBuf(key_id);
      return (1);
    }
    memcpy(key_id->chars, cJSON_GetObjectItemCaseSensitive(json, "key_id")->valuestring, key_id->len);
  }
  else
  {
    pelz_log(LOG_ERR, "No value in JSON key: key_id.");
    freeCharBuf(key_id);
    return (1);
  }
  if (!cJSON_IsNumber(cJSON_GetObjectItem(json, "dec_data_len")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: dec_data_len. Data type should be integer.");
    freeCharBuf(key_id);
    return (1);
  }
  *data = newCharBuf(cJSON_GetObjectItemCaseSensitive(json, "dec_data_len")->valueint);
  if (!cJSON_IsString(cJSON_GetObjectItem(json, "dec_data")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: dec_data. Data type should be string.");
    freeCharBuf(key_id);
    freeCharBuf(data);
    return (1);
  }
  if (cJSON_GetObjectItemCaseSensitive(json, "dec_data")->valuestring != NULL)
  {
    if (strlen(cJSON_GetObjectItemCaseSensitive(json, "dec_data")->valuestring) != data->len)
    {
      pelz_log(LOG_ERR, "Length of value in JSON key: dec_data does not match value in JSON key: dec_data_len.");
      freeCharBuf(key_id);
      freeCharBuf(data);
      return (1);
    }
    memcpy(data->chars, cJSON_GetObjectItemCaseSensitive(json, "dec_data")->valuestring, data->len);
  }
  else
  {
    pelz_log(LOG_ERR, "No value in JSON key: dec_data.");
    freeCharBuf(key_id);
    freeCharBuf(data);
    return (1);
  }
  return (0);
}
