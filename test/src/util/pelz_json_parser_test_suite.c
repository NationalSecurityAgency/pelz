/*
 * pelz_json_parser_suite.c
 */

#include "pelz_json_parser_test_suite.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cjson/cJSON.h>

#include <CharBuf.h>
#include <pelz_log.h>

// Adds all key table tests to main test runner.
int pelz_json_parser_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test JSON Encryption Request Parser", test_encrypt_parser))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test JSON Decryption Request Parser", test_decrypt_parser))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Decoding of JSON formatted Request", test_request_decoder))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Encoding of JSON formatted Response Message", test_message_encoder))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Encoding of JSON formatted Error Message", test_error_message_encoder))
  {
    return (1);
  }
  return (0);
}

void test_encrypt_parser(void)
{
  cJSON *json;
  CharBuf key_id;
  CharBuf data;

  //Valid Test Values
  char *json_key_id = "file:/test/key1.txt";
  int json_key_id_len = 19;
  char *enc_data = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY=\n";
  int enc_data_len = 45;
  char *dec_data = "SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\n";
  int dec_data_len = 57;

  //Building of a standard valid JSON request
  json = cJSON_CreateObject();
  cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(1));
  cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id));
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len));
  cJSON_AddItemToObject(json, "enc_data", cJSON_CreateString(enc_data));
  cJSON_AddItemToObject(json, "enc_data_len", cJSON_CreateNumber(enc_data_len));
  cJSON_AddItemToObject(json, "dec_data", cJSON_CreateString(dec_data));
  cJSON_AddItemToObject(json, "dec_data_len", cJSON_CreateNumber(dec_data_len));

  //Test standard valid JSON request
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 0);
  CU_ASSERT(key_id.len == json_key_id_len);
  CU_ASSERT(memcmp(key_id.chars, json_key_id, key_id.len) == 0);
  CU_ASSERT(data.len == enc_data_len);
  CU_ASSERT(memcmp(data.chars, enc_data, data.len) == 0);
  freeCharBuf(&key_id);
  freeCharBuf(&data);

  //Test check of JSON request hasObject
  cJSON_DeleteItemFromObject(json, "key_id");
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
  cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id));

  cJSON_DeleteItemFromObject(json, "key_id_len");
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len));

  cJSON_DeleteItemFromObject(json, "enc_data");
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
  cJSON_AddItemToObject(json, "enc_data", cJSON_CreateString(enc_data));

  cJSON_DeleteItemFromObject(json, "enc_data_len");
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
  cJSON_AddItemToObject(json, "enc_data_len", cJSON_CreateNumber(enc_data_len));

  cJSON_DeleteItemFromObject(json, "dec_data");
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 0);
  freeCharBuf(&key_id);
  freeCharBuf(&data);
  cJSON_AddItemToObject(json, "dec_data", cJSON_CreateString(dec_data));

  cJSON_DeleteItemFromObject(json, "dec_data_len");
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 0);
  freeCharBuf(&key_id);
  freeCharBuf(&data);
  cJSON_AddItemToObject(json, "dec_data_len", cJSON_CreateNumber(dec_data_len));

  //Test check of JSON request isNumber
  cJSON_DeleteItemFromObject(json, "key_id_len");
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateString("19"));
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "key_id_len");
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len));

  cJSON_DeleteItemFromObject(json, "enc_data_len");
  cJSON_AddItemToObject(json, "enc_data_len", cJSON_CreateString("45"));
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "enc_data_len");
  cJSON_AddItemToObject(json, "enc_data_len", cJSON_CreateNumber(enc_data_len));

  //Test check of JSON request isString
  cJSON_DeleteItemFromObject(json, "key_id");
  cJSON_AddItemToObject(json, "key_id", cJSON_CreateNumber(5482));
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "key_id");
  cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id));

  cJSON_DeleteItemFromObject(json, "enc_data");
  cJSON_AddItemToObject(json, "enc_data", cJSON_CreateNumber(6842));
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "enc_data");
  cJSON_AddItemToObject(json, "enc_data", cJSON_CreateString(enc_data));

  //Test check of JSON request string length match
  cJSON_DeleteItemFromObject(json, "key_id_len");
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(20));
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "key_id_len");
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len));

  cJSON_DeleteItemFromObject(json, "enc_data_len");
  cJSON_AddItemToObject(json, "enc_data_len", cJSON_CreateNumber(50));
  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "enc_data_len");
  cJSON_AddItemToObject(json, "enc_data_len", cJSON_CreateNumber(enc_data_len));

  //Clean-up JSON
  cJSON_Delete(json);
}

void test_decrypt_parser(void)
{
  cJSON *json;
  CharBuf key_id;
  CharBuf data;

  //Valid Test Values
  char *json_key_id = "file:/test/key1.txt";
  int json_key_id_len = 19;
  char *enc_data = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY=\n";
  int enc_data_len = 45;
  char *dec_data = "SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\n";
  int dec_data_len = 57;

  //Building of a standard valid JSON request
  json = cJSON_CreateObject();
  cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(2));
  cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id));
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len));
  cJSON_AddItemToObject(json, "enc_data", cJSON_CreateString(enc_data));
  cJSON_AddItemToObject(json, "enc_data_len", cJSON_CreateNumber(enc_data_len));
  cJSON_AddItemToObject(json, "dec_data", cJSON_CreateString(dec_data));
  cJSON_AddItemToObject(json, "dec_data_len", cJSON_CreateNumber(dec_data_len));

  //Test standard valid JSON request
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 0);
  CU_ASSERT(key_id.len == json_key_id_len);
  CU_ASSERT(memcmp(key_id.chars, json_key_id, key_id.len) == 0);
  CU_ASSERT(data.len == dec_data_len);
  CU_ASSERT(memcmp(data.chars, dec_data, data.len) == 0);
  freeCharBuf(&key_id);
  freeCharBuf(&data);

  //Test check of JSON request hasObject
  cJSON_DeleteItemFromObject(json, "key_id");
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
  cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id));

  cJSON_DeleteItemFromObject(json, "key_id_len");
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len));

  cJSON_DeleteItemFromObject(json, "dec_data");
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
  cJSON_AddItemToObject(json, "dec_data", cJSON_CreateString(dec_data));

  cJSON_DeleteItemFromObject(json, "dec_data_len");
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
  cJSON_AddItemToObject(json, "dec_data_len", cJSON_CreateNumber(dec_data_len));

  cJSON_DeleteItemFromObject(json, "enc_data");
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 0);
  freeCharBuf(&key_id);
  freeCharBuf(&data);
  cJSON_AddItemToObject(json, "enc_data", cJSON_CreateString(enc_data));

  cJSON_DeleteItemFromObject(json, "enc_data_len");
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 0);
  freeCharBuf(&key_id);
  freeCharBuf(&data);
  cJSON_AddItemToObject(json, "enc_data_len", cJSON_CreateNumber(enc_data_len));

  //Test check of JSON request isNumber
  cJSON_DeleteItemFromObject(json, "key_id_len");
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateString("19"));
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "key_id_len");
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len));

  cJSON_DeleteItemFromObject(json, "dec_data_len");
  cJSON_AddItemToObject(json, "dec_data_len", cJSON_CreateString("57"));
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "dec_data_len");
  cJSON_AddItemToObject(json, "dec_data_len", cJSON_CreateNumber(dec_data_len));

  //Test check of JSON request isString
  cJSON_DeleteItemFromObject(json, "key_id");
  cJSON_AddItemToObject(json, "key_id", cJSON_CreateNumber(5482));
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "key_id");
  cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id));

  cJSON_DeleteItemFromObject(json, "dec_data");
  cJSON_AddItemToObject(json, "dec_data", cJSON_CreateNumber(6842));
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "dec_data");
  cJSON_AddItemToObject(json, "dec_data", cJSON_CreateString(dec_data));

  //Test check of JSON request string length match
  cJSON_DeleteItemFromObject(json, "key_id_len");
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(20));
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "key_id_len");
  cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len));

  cJSON_DeleteItemFromObject(json, "dec_data_len");
  cJSON_AddItemToObject(json, "dec_data_len", cJSON_CreateNumber(50));
  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
  cJSON_DeleteItemFromObject(json, "dec_data_len");
  cJSON_AddItemToObject(json, "dec_data_len", cJSON_CreateNumber(dec_data_len));

  //Clean-up JSON
  cJSON_Delete(json);
}

void test_request_decoder(void)
{
  CharBuf request;
  char *tmp;
  RequestType request_type;
  CharBuf key_id;
  CharBuf data;
  cJSON *json_enc;
  cJSON *json_dec;

  char *invalid_request[4] = {
    "{\"key_id_len\": 28, \"key_id\": \"file:/test/testkeys/key2.txt\"}",
    "{\"request_type\": \"one\"}", "{\"request_type\": 0}", "{\"request_type\": 3}"
  };
  char *json_key_id[6] = {
    "file:/test/key1.txt", "file:/test/key2.txt", "file:/test/key3.txt",
    "file:/test/key4.txt", "file:/test/key5.txt", "file:/test/key6.txt"
  };
  int json_key_id_len = 19;

  char *enc_data[6] = {
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY=\n", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=\n",
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY\n", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n",
    "QUJDREVGR0hJSktMTU5PUA==\n", "YWJjZGVmZ2hpamtsbW5vcA==\n"
  };
  int enc_data_len[6] = {
    45, 45, 33, 33, 25, 25
  };
  char *dec_data[6] = {
    "SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\n",
    "txQhouR/i5+lycST2QXuN39gQqVQYVy9mWf3RdSdXfZNUy4CsQqwBg==\n",
    "+n4yYCmMXyNbyEtsJuFlBtkCbVDXhjVRON/osW5dbz8=\n", "BtIjIgvCaVBwUi5jTOZyIx2yJamqvrR0BZWLFVufz9w=\n",
    "K2YZ6dTyLpmXRseKg+wwlPUZCnFmYBEn\n", "K6iS75+hIrCNuo9LWeEhjDQ2L9miNR07\n"
  };
  int dec_data_len[6] = {
    57, 57, 45, 45, 33, 33
  };

  pelz_log(LOG_DEBUG, "Start Request Decoder Test");
  //Test Invalid Requests with bad request_types
  for (int i = 0; i < 4; i++)
  {
    request = newCharBuf(strlen(invalid_request[i]));
    memcpy(request.chars, invalid_request[i], request.len);
    CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 1);
    freeCharBuf(&request);
    request_type = 0;
  }

  //Building of the json request and most combinations
  json_enc = cJSON_CreateObject();
  json_dec = cJSON_CreateObject();
  cJSON_AddItemToObject(json_enc, "request_type", cJSON_CreateNumber(1));
  cJSON_AddItemToObject(json_dec, "request_type", cJSON_CreateNumber(2));

  tmp = cJSON_PrintUnformatted(json_enc);
  request = newCharBuf(strlen(tmp));
  memcpy(request.chars, tmp, request.len);
  free(tmp);
  CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 1);
  freeCharBuf(&request);
  request_type = 0;

  tmp = cJSON_PrintUnformatted(json_dec);
  request = newCharBuf(strlen(tmp));
  memcpy(request.chars, tmp, request.len);
  free(tmp);
  CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 1);
  freeCharBuf(&request);
  request_type = 0;

  for (int i = 0; i < 6; i++)
  {
    cJSON_AddItemToObject(json_enc, "key_id", cJSON_CreateString(json_key_id[i]));
    cJSON_AddItemToObject(json_enc, "key_id_len", cJSON_CreateNumber(json_key_id_len));
    cJSON_AddItemToObject(json_dec, "key_id", cJSON_CreateString(json_key_id[i]));
    cJSON_AddItemToObject(json_dec, "key_id_len", cJSON_CreateNumber(json_key_id_len));
    cJSON_AddItemToObject(json_enc, "enc_data", cJSON_CreateString(enc_data[i]));
    cJSON_AddItemToObject(json_dec, "dec_data", cJSON_CreateString(dec_data[i]));
    cJSON_AddItemToObject(json_enc, "enc_data_len", cJSON_CreateNumber(enc_data_len[i]));
    cJSON_AddItemToObject(json_dec, "dec_data_len", cJSON_CreateNumber(dec_data_len[i]));

    //Creating the request CharBuf for the JSON then testing request_decoder for encryption
    tmp = cJSON_PrintUnformatted(json_enc);
    request = newCharBuf(strlen(tmp));
    memcpy(request.chars, tmp, request.len);
    free(tmp);
    CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 0);
    CU_ASSERT(request_type == 1);
    CU_ASSERT(key_id.len == json_key_id_len);
    CU_ASSERT(memcmp(key_id.chars, json_key_id[i], key_id.len) == 0);
    CU_ASSERT(data.len == enc_data_len[i]);
    CU_ASSERT(memcmp(data.chars, enc_data[i], data.len) == 0);
    freeCharBuf(&request);
    request_type = 0;
    freeCharBuf(&key_id);
    freeCharBuf(&data);

    //Creating the request CharBuf for the JSON then testing request_decoder for decryption
    tmp = cJSON_PrintUnformatted(json_dec);
    request = newCharBuf(strlen(tmp));
    memcpy(request.chars, tmp, request.len);
    free(tmp);
    CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 0);
    CU_ASSERT(request_type == 2);
    CU_ASSERT(key_id.len == json_key_id_len);
    CU_ASSERT(memcmp(key_id.chars, json_key_id[i], key_id.len) == 0);
    CU_ASSERT(data.len == dec_data_len[i]);
    CU_ASSERT(memcmp(data.chars, dec_data[i], data.len) == 0);
    freeCharBuf(&request);
    request_type = 0;
    freeCharBuf(&key_id);
    freeCharBuf(&data);

    //Free the cJSON Objects to allow the addition of the next Object per the loop
    cJSON_DeleteItemFromObject(json_dec, "dec_data");
    cJSON_DeleteItemFromObject(json_dec, "dec_data_len");
    cJSON_DeleteItemFromObject(json_enc, "enc_data");
    cJSON_DeleteItemFromObject(json_enc, "enc_data_len");
    cJSON_DeleteItemFromObject(json_enc, "key_id");
    cJSON_DeleteItemFromObject(json_enc, "key_id_len");
    cJSON_DeleteItemFromObject(json_dec, "key_id");
    cJSON_DeleteItemFromObject(json_dec, "key_id_len");
  }

  cJSON_Delete(json_enc);
  cJSON_Delete(json_dec);
}

void test_message_encoder(void)
{
  RequestType request_type[4] = { 0, 1, 2, 3 };
  CharBuf key_id;
  CharBuf data;
  CharBuf message;
  char *test[5] = { "file:/test/key1.txt", "test/key1.txt", "file", "anything", "" };
  char *valid_enc_message[5] =
    { "{\"key_id\":\"file:/test/key1.txt\",\"key_id_len\":19,\"enc_out\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"enc_out_len\":57}",
    "{\"key_id\":\"test/key1.txt\",\"key_id_len\":13,\"enc_out\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"enc_out_len\":57}",
    "{\"key_id\":\"file\",\"key_id_len\":4,\"enc_out\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"enc_out_len\":57}",
    "{\"key_id\":\"anything\",\"key_id_len\":8,\"enc_out\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"enc_out_len\":57}",
    "{\"key_id\":\"\",\"key_id_len\":0,\"enc_out\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"enc_out_len\":57}"
  };
  char *valid_dec_message[5] =
    { "{\"key_id\":\"file:/test/key1.txt\",\"key_id_len\":19,\"dec_out\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"dec_out_len\":57}",
    "{\"key_id\":\"test/key1.txt\",\"key_id_len\":13,\"dec_out\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"dec_out_len\":57}",
    "{\"key_id\":\"file\",\"key_id_len\":4,\"dec_out\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"dec_out_len\":57}",
    "{\"key_id\":\"anything\",\"key_id_len\":8,\"dec_out\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"dec_out_len\":57}",
    "{\"key_id\":\"\",\"key_id_len\":0,\"dec_out\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"dec_out_len\":57}"
  };

  //Start Message Encoder Test
  pelz_log(LOG_DEBUG, "Start Message Encoder Test");

  data = newCharBuf(57);
  memcpy(data.chars, "SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\n", data.len);
  key_id = newCharBuf(strlen(test[0]));
  memcpy(key_id.chars, test[0], key_id.len);
  CU_ASSERT(message_encoder(request_type[0], key_id, data, &message) == 1);
  CU_ASSERT(message_encoder(request_type[3], key_id, data, &message) == 1);
  freeCharBuf(&key_id);

  for (int i = 0; i < 5; i++)
  {
    key_id = newCharBuf(strlen(test[i]));
    memcpy(key_id.chars, test[i], key_id.len);
    CU_ASSERT(message_encoder(request_type[1], key_id, data, &message) == 0);
    CU_ASSERT(memcmp(message.chars, valid_enc_message[i], message.len) == 0);
    freeCharBuf(&message);
    CU_ASSERT(message_encoder(request_type[2], key_id, data, &message) == 0);
    CU_ASSERT(memcmp(message.chars, valid_dec_message[i], message.len) == 0);
    freeCharBuf(&message);
    freeCharBuf(&key_id);
  }
  freeCharBuf(&data);
}

void test_error_message_encoder(void)
{
  pelz_log(LOG_DEBUG, "Test err msg");
  char *err_msg[5] = {
    "Missing Data", "missing data", "akdifid", "Error", "Any message"
  };
  CharBuf message;

  for (int i = 0; i < 5; i++)
  {
    CU_ASSERT(error_message_encoder(&message, err_msg[i]) == 0);
    pelz_log(LOG_DEBUG, "Error Message: %.*s", message.len, message.chars);
    freeCharBuf(&message);
  }
}
