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
  if(NULL == CU_add_test(suite, "Test JSON Encryption Request Parser", test_encrypt_parser))
		  {
    return (1);
		  }
  if(NULL == CU_add_test(suite, "Test JSON Decryption Request Parser", test_decrypt_parser))
		  {
    return (1);
		  }
  if(NULL == CU_add_test(suite, "Test Decoding of JSON formatted Request", test_request_decoder))
		  {
    return (1);
		  }
  if(NULL == CU_add_test(suite, "Test Encoding of JSON formatted Response Message", test_message_encoder))
		  {
    return (1);
		  }
  if(NULL == CU_add_test(suite, "Test Encoding of JSON formatted Error Message", test_error_message_encoder))
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
  int request[3] = {1, 2, 3};
  char *json_key_id[4] = {"file:/test/key1.txt", "test/key1.txt", "Anything", "25416857"};
  int json_key_id_len[4] = {18, 12, 8, 8};
  char *enc_data[2] = {"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY=\n", "Anything"};
  int enc_data_len[2] = {44, 8};
  char *dec_data = "SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\n";
  int dec_data_len = 56;

  json = cJSON_CreateObject();
  for(int i = 0; i < 3; i++)
  {
	cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(request[i]));
	CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	if (key_id.chars != NULL)
	  freeCharBuf(&key_id);
	if (data.chars != NULL)
	  freeCharBuf(&data);
	cJSON_DeleteItemFromObject(json, "request_type");
	for(int j = 0; j < 4; j++)
	{
	  cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id[j]));
	  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	  	if (key_id.chars != NULL)
	  	  freeCharBuf(&key_id);
	  	if (data.chars != NULL)
	  	  freeCharBuf(&data);
	  cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(request[i]));
	  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	  	if (key_id.chars != NULL)
	  	  freeCharBuf(&key_id);
	  	if (data.chars != NULL)
	  	  freeCharBuf(&data);
   	  JSON_DeleteItemFromObject(json, "request_type");
	  JSON_DeleteItemFromObject(json, "key_id");
	  for(int x = 0; x < 4; x++)
	  {
		cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len[x]));
		CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	 	if (key_id.chars != NULL)
	  	  freeCharBuf(&key_id);
	  	if (data.chars != NULL)
	  	  freeCharBuf(&data);
	  	cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id[j]));
	  	CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	  	  if (key_id.chars != NULL)
	  		freeCharBuf(&key_id);
	  	  if (data.chars != NULL)
	  		freeCharBuf(&data);
	    cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(request[i]));
	    CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	  	if (key_id.chars != NULL)
	  	  freeCharBuf(&key_id);
	  	if (data.chars != NULL)
	  	  freeCharBuf(&data);
	  	JSON_DeleteItemFromObject(json, "request_type");
	  	JSON_DeleteItemFromObject(json, "key_id");
	  	JSON_DeleteItemFromObject(json, "key_id_len");
	  	for(int y = 0; y < 2; y++)
	  	{
	      cJSON_AddItemToObject(json, "enc_data", cJSON_CreateString(enc_data[y]));
		  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
  	  	  if (key_id.chars != NULL)
	  	    freeCharBuf(&key_id);
	      if (data.chars != NULL)
	  	    freeCharBuf(&data);
	      cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len[x]));
	      CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	      if (key_id.chars != NULL)
	    	freeCharBuf(&key_id);
	      if (data.chars != NULL)
	      	freeCharBuf(&data);
	      cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id[j]));
	      CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	      if (key_id.chars != NULL)
	      	freeCharBuf(&key_id);
	      if (data.chars != NULL)
	      	freeCharBuf(&data);
	      cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(request[i]));
	      CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	      if (key_id.chars != NULL)
	      	freeCharBuf(&key_id);
	      if (data.chars != NULL)
	      	freeCharBuf(&data);
	      JSON_DeleteItemFromObject(json, "request_type");
	      JSON_DeleteItemFromObject(json, "key_id");
	      JSON_DeleteItemFromObject(json, "key_id_len");
	      JSON_DeleteItemFromObject(json, "enc_data");
	      for(int z = 0; z < 2; z++)
	      {
	    	cJSON_AddItemToObject(json, "enc_data_len", cJSON_CreateNumber(enc_data_len[z]));
	  		CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	  	 	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	    cJSON_AddItemToObject(json, "dec_data", cJSON_CreateString(dec_data));
	  	  	CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	  	  	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	  	cJSON_AddItemToObject(json, "dec_data_len", cJSON_CreateNumber(dec_data_len));
	  	  	CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	  	  	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	    cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(request[i]));
	  	  	CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	  	  	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	    cJSON_AddItemToObject(json, "enc_data", cJSON_CreateString(enc_data[y]));
	  	  	CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	  	    if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	  	cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len[x]));
	  	  	CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	  	  	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	  	cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id[j]));
	  	  	if (j == x && y == x)
	  	  	  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 0);
	  	  	else
	  	  	  CU_ASSERT(encrypt_parser(json, &key_id, &data) == 1);
	  	  	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	    JSON_DeleteItemFromObject(json, "request_type");
	  	  	JSON_DeleteItemFromObject(json, "key_id");
	  	  	JSON_DeleteItemFromObject(json, "key_id_len");
	  	  	JSON_DeleteItemFromObject(json, "enc_data");
	  	    JSON_DeleteItemFromObject(json, "enc_data_len");
	  	    JSON_DeleteItemFromObject(json, "dec_data");
	  	    JSON_DeleteItemFromObject(json, "dec_data_len");
	      }
	  	}
	  }
	}
  }
  cJSON_Delete(json);
}

void test_decrypt_parser(void)
{
  cJSON *json;
  CharBuf key_id;
  CharBuf data;
  int request[3] = {1, 2, 3};
  char *json_key_id[4] = {"file:/test/key1.txt", "test/key1.txt", "Anything", "25416857"};
  int json_key_id_len[4] = {18, 12, 8, 8};
  char *dec_data[2] = {"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\n", "Anything"};
  int dec_data_len[2] = {56, 8};
  char *enc_data = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY=\n";
  int enc_data_len = 44;

  json = cJSON_CreateObject();
  for(int i = 0; i < 3; i++)
  {
	cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(request[i]));
	CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	if (key_id.chars != NULL)
	  freeCharBuf(&key_id);
	if (data.chars != NULL)
	  freeCharBuf(&data);
	cJSON_DeleteItemFromObject(json, "request_type");
	for(int j = 0; j < 4; j++)
	{
	  cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id[j]));
	  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	  	if (key_id.chars != NULL)
	  	  freeCharBuf(&key_id);
	  	if (data.chars != NULL)
	  	  freeCharBuf(&data);
	  cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(request[i]));
	  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	  	if (key_id.chars != NULL)
	  	  freeCharBuf(&key_id);
	  	if (data.chars != NULL)
	  	  freeCharBuf(&data);
   	  JSON_DeleteItemFromObject(json, "request_type");
	  JSON_DeleteItemFromObject(json, "key_id");
	  for(int x = 0; x < 4; x++)
	  {
		cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len[x]));
		CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	 	if (key_id.chars != NULL)
	  	  freeCharBuf(&key_id);
	  	if (data.chars != NULL)
	  	  freeCharBuf(&data);
	  	cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id[j]));
	  	CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	  	  if (key_id.chars != NULL)
	  		freeCharBuf(&key_id);
	  	  if (data.chars != NULL)
	  		freeCharBuf(&data);
	    cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(request[i]));
	    CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	  	if (key_id.chars != NULL)
	  	  freeCharBuf(&key_id);
	  	if (data.chars != NULL)
	  	  freeCharBuf(&data);
	  	JSON_DeleteItemFromObject(json, "request_type");
	  	JSON_DeleteItemFromObject(json, "key_id");
	  	JSON_DeleteItemFromObject(json, "key_id_len");
	  	for(int y = 0; y < 2; y++)
	  	{
	      cJSON_AddItemToObject(json, "enc_data", cJSON_CreateString(enc_data[y]));
		  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
  	  	  if (key_id.chars != NULL)
	  	    freeCharBuf(&key_id);
	      if (data.chars != NULL)
	  	    freeCharBuf(&data);
	      cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len[x]));
	      CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	      if (key_id.chars != NULL)
	    	freeCharBuf(&key_id);
	      if (data.chars != NULL)
	      	freeCharBuf(&data);
	      cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id[j]));
	      CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	      if (key_id.chars != NULL)
	      	freeCharBuf(&key_id);
	      if (data.chars != NULL)
	      	freeCharBuf(&data);
	      cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(request[i]));
	      CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	      if (key_id.chars != NULL)
	      	freeCharBuf(&key_id);
	      if (data.chars != NULL)
	      	freeCharBuf(&data);
	      JSON_DeleteItemFromObject(json, "request_type");
	      JSON_DeleteItemFromObject(json, "key_id");
	      JSON_DeleteItemFromObject(json, "key_id_len");
	      JSON_DeleteItemFromObject(json, "enc_data");
	      for(int z = 0; z < 2; z++)
	      {
	    	cJSON_AddItemToObject(json, "enc_data_len", cJSON_CreateNumber(enc_data_len[z]));
	  		CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	  	 	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	    cJSON_AddItemToObject(json, "dec_data", cJSON_CreateString(dec_data));
	  	  	CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	  	  	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	  	cJSON_AddItemToObject(json, "dec_data_len", cJSON_CreateNumber(dec_data_len));
	  	  	CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	  	  	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	    cJSON_AddItemToObject(json, "request_type", cJSON_CreateNumber(request[i]));
	  	  	CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	  	  	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	    cJSON_AddItemToObject(json, "enc_data", cJSON_CreateString(enc_data[y]));
	  	  	CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	  	    if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	  	cJSON_AddItemToObject(json, "key_id_len", cJSON_CreateNumber(json_key_id_len[x]));
	  	  	CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	  	  	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	  	cJSON_AddItemToObject(json, "key_id", cJSON_CreateString(json_key_id[j]));
	  	  	if (j == x && y == x)
	  	  	  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 0);
	  	  	else
	  	  	  CU_ASSERT(decrypt_parser(json, &key_id, &data) == 1);
	  	  	if (key_id.chars != NULL)
	  	  	  freeCharBuf(&key_id);
	  	  	if (data.chars != NULL)
	  	  	  freeCharBuf(&data);
	  	    JSON_DeleteItemFromObject(json, "request_type");
	  	  	JSON_DeleteItemFromObject(json, "key_id");
	  	  	JSON_DeleteItemFromObject(json, "key_id_len");
	  	  	JSON_DeleteItemFromObject(json, "enc_data");
	  	    JSON_DeleteItemFromObject(json, "enc_data_len");
	  	    JSON_DeleteItemFromObject(json, "dec_data");
	  	    JSON_DeleteItemFromObject(json, "dec_data_len");
	      }
	  	}
	  }
	}
  }
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
  char *json_key_id[6] = {"file:/test/key1.txt", "file:/test/key2.txt", "file:/test/key3.txt",
			  "file:/test/key4.txt", "file:/test/key5.txt", "file:/test/key6.txt"};
  int json_key_id_len = 18;
  char *enc_data[6] = {"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY=\n", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=\n",
			 "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY\n", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n",
			 "QUJDREVGR0hJSktMTU5PUA==\n", "YWJjZGVmZ2hpamtsbW5vcA==\n"};
  int enc_data_len[6] = {44, 44, 32, 32, 24, 24};
  char *dec_data[6] = {"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\n", "txQhouR/i5+lycST2QXuN39gQqVQYVy9mWf3RdSdXfZNUy4CsQqwBg==\n",
			 "+n4yYCmMXyNbyEtsJuFlBtkCbVDXhjVRON/osW5dbz8=\n", "BtIjIgvCaVBwUi5jTOZyIx2yJamqvrR0BZWLFVufz9w=\n",
			 "K2YZ6dTyLpmXRseKg+wwlPUZCnFmYBEn\n", "K6iS75+hIrCNuo9LWeEhjDQ2L9miNR07\n"};
  int dec_data_len[6] = {56, 56, 44, 44, 32, 32};

  pelz_log(LOG_DEBUG, "Start Request Decoder Test");
  json_enc = cJSON_CreateObject();
  json_dec = cJSON_CreateObject();
  cJSON_AddItemToObject(json_enc, "request_type", cJSON_CreateNumber(1));
  cJSON_AddItemToObject(json_dec, "request_type", cJSON_CreateNumber(2));
  
  tmp = cJSON_PrintUnformatted(json_enc);
  request = newCharBuf(strlen(tmp));
  memcpy(request.chars, tmp, request.len);
  free(tmp);
  CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 0);
  freeCharBuf(&request);
  request_type = 0;
  if (key_id.chars != NULL)
    freeCharBuf(&key_id);
  if (data.chars != NULL)
    freeCharBuf(&data);

  tmp = cJSON_PrintUnformatted(json_dec);
  request = newCharBuf(strlen(tmp));
  memcpy(request.chars, tmp, request.len);
  free(tmp);
  CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 1);
  freeCharBuf(&request);
  request_type = 0;
  if (key_id.chars != NULL)
    freeCharBuf(&key_id);
  if (data.chars != NULL)
    freeCharBuf(&data);

  for (int i = 0; i < 6; i++)
  {
	cJSON_AddItemToObject(json_enc, "key_id", cJSON_CreateString(json_key_id[i]));
	cJSON_AddItemToObject(json_enc, "key_id_len", cJSON_CreateNumber(json_key_id_len));
	cJSON_AddItemToObject(json_dec, "key_id", cJSON_CreateString(json_key_id[i]));
	cJSON_AddItemToObject(json_dec, "key_id_len", cJSON_CreateNumber(json_key_id_len));

	tmp = cJSON_PrintUnformatted(json_enc);
    	request = newCharBuf(strlen(tmp));
	memcpy(request.chars, tmp, request.len);
	free(tmp);
	CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 0);
	freeCharBuf(&request);
	request_type = 0;
	if (key_id.chars != NULL)
	  freeCharBuf(&key_id);
	if (data.chars != NULL)
	  freeCharBuf(&data);

    	tmp = cJSON_PrintUnformatted(json_dec);
    	request = newCharBuf(strlen(tmp));
  	memcpy(request.chars, tmp, request.len);
  	free(tmp);
  	CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 1);
  	freeCharBuf(&request);
  	request_type = 0;
  	if (key_id.chars != NULL)
  	  freeCharBuf(&key_id);
    	if (data.chars != NULL)
	  freeCharBuf(&data);

	for (int j = 0; j < 6; j++)
	{
	  cJSON_AddItemToObject(json_enc, "enc_data", cJSON_CreateString(enc_data[j]));
	  cJSON_AddItemToObject(json_dec, "dec_data", cJSON_CreateString(dec_data[j]));

	  tmp = cJSON_PrintUnformatted(json_enc);
	  request = newCharBuf(strlen(tmp));
	  memcpy(request.chars, tmp, request.len);
	  free(tmp);
	  CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 0);
	  freeCharBuf(&request);
	  request_type = 0;
  	  if (key_id.chars != NULL)
  	    freeCharBuf(&key_id);
      	  if (data.chars != NULL)
  	    freeCharBuf(&data);

	  tmp = cJSON_PrintUnformatted(json_dec);
  	  request = newCharBuf(strlen(tmp));
  	  memcpy(request.chars, tmp, request.len);
  	  free(tmp);
  	  CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 1);
  	  freeCharBuf(&request);
  	  request_type = 0;
  	  if (key_id.chars != NULL)
  	    freeCharBuf(&key_id);
      	  if (data.chars != NULL)
  	    freeCharBuf(&data);

	  cJSON_AddItemToObject(json_enc, "enc_data_len", cJSON_CreateNumber(enc_data_len[j]));
	  cJSON_AddItemToObject(json_dec, "dec_data_len", cJSON_CreateNumber(dec_data_len[j]));

	  tmp = cJSON_PrintUnformatted(json_enc);
	  request = newCharBuf(strlen(tmp));
	  memcpy(request.chars, tmp, request.len);
	  cJSON_Delete(json_enc);
	  free(tmp);
	  CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 0);
	  freeCharBuf(&request);
	  request_type = 0;
	  freeCharBuf(&key_id);
	  freeCharBuf(&data);

	  tmp = cJSON_PrintUnformatted(json_dec);
  	  request = newCharBuf(strlen(tmp));
  	  memcpy(request.chars, tmp, request.len);
  	  cJSON_Delete(json_dec);
  	  free(tmp);
  	  CU_ASSERT(request_decoder(request, &request_type, &key_id, &data) == 0);
  	  freeCharBuf(&request);
  	  request_type = 0;
  	  freeCharBuf(&key_id);
  	  freeCharBuf(&data);
	}
  }
}

void test_message_encoder(void)
{
	RequestType request_type[4] = {0, 1, 2, 3};
	CharBuf key_id;
	CharBuf data;
	CharBuf message;
	char *test[5] = {"file:/test/key1.txt", "test/key1.txt", "file", "anything", ""};

	pelz_log(LOG_DEBUG, "Start Message Encoder Test");
	data = newCharBuf(57);
	memcpy(data.chars, "SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\n", data.len);
	for (int i = 0; i < 4; i++)
	{
	  
	  for (int j = 0; j < 5; j++)
	  {
		key_id = newCharBuf(strlen(test[j]));
		memcpy(key_id.chars, test[j], key_id.len);
		pelz_log(LOG_DEBUG, "Request Message Values: %d, %s, %d, %s, %d", request_type[i], key_id.chars, (int) key_id.len, data.chars, (int) data.len);
		if (i == 1 || i == 2)
		{
		  CU_ASSERT(message_encoder(request_type[i], key_id, data, &message) == 0);
		  freeCharBuf(&message);
		  freeCharBuf(&data);
		}
		else
		{
		  CU_ASSERT(message_encoder(request_type[i], key_id, data, &message) == 1);
		  freeCharBuf(&data);
		}
	  }
	}
}

void test_error_message_encoder(void)
{
	pelz_log(LOG_DEBUG, "Test err msg");
	char *err_msg[5] = {"Missing Data", "missing data", "akdifid", "Error", "Any message"};
	CharBuf message;

	for (int i = 0; i < 5; i++)
	{
	  CU_ASSERT(error_message_encoder(&message, err_msg[i]) == 0);
	  pelz_log(LOG_DEBUG, "Error Message: %s", message.chars);
	  freeCharBuf(&message);
	}
}
