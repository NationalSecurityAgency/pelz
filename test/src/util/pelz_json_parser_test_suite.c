/*
 * pelz_json_parser_suite.c
 */

#include "pelz_json_parser_test_suite.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cjson/cJSON.h>

#include <charbuf.h>
#include <pelz_log.h>
#include "kmyth/formatting_tools.h"

// Adds all key table tests to main test runner.
int pelz_json_parser_suite_add_tests(CU_pSuite suite)
{
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

void test_request_decoder(void)
{
  charbuf request;
  char *tmp;
  RequestType request_type;
  charbuf key_id;
  charbuf data;
  charbuf request_sig;
  charbuf requestor_cert;
  charbuf tag;
  charbuf iv;
  charbuf cipher_name;
  cJSON *json_enc;
  cJSON *json_dec;
  cJSON *json_enc_signed;
  cJSON *json_dec_signed;

  const char *invalid_request[4] = {
    "{\"key_id\": \"file:/test/testkeys/key2.txt\"}",
    "{\"request_type\": \"one\"}", "{\"request_type\": 0}", "{\"request_type\": 7}"
  };
  const char *json_key_id[6] = {
    "file:/test/key1.txt", "file:/test/key2.txt", "file:/test/key3.txt",
    "file:/test/key4.txt", "file:/test/key5.txt", "file:/test/key6.txt"
  };
  unsigned int json_key_id_len = 19;

  const char *enc_data[6] = {
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY=\n", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=\n",
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY\n", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n",
    "QUJDREVGR0hJSktMTU5PUA==\n", "YWJjZGVmZ2hpamtsbW5vcA==\n"
  };
  unsigned int enc_data_len[6] = {
    45, 45, 33, 33, 25, 25
  };
  const char *dec_data[6] = {
    "SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\n",
    "txQhouR/i5+lycST2QXuN39gQqVQYVy9mWf3RdSdXfZNUy4CsQqwBg==\n",
    "+n4yYCmMXyNbyEtsJuFlBtkCbVDXhjVRON/osW5dbz8=\n", "BtIjIgvCaVBwUi5jTOZyIx2yJamqvrR0BZWLFVufz9w=\n",
    "K2YZ6dTyLpmXRseKg+wwlPUZCnFmYBEn\n", "K6iS75+hIrCNuo9LWeEhjDQ2L9miNR07\n"
  };
  unsigned int dec_data_len[6] = {
    57, 57, 45, 45, 33, 33
  };

  const char* cipher_name_str = "cipher_name";

  pelz_log(LOG_DEBUG, "Start Request Decoder Test");
  //Test Invalid Requests with bad request_types
  for (int i = 0; i < 4; i++)
  {
    request = new_charbuf(strlen(invalid_request[i]));
    memcpy(request.chars, invalid_request[i], request.len);
    CU_ASSERT(request_decoder(request, &request_type, &key_id, &cipher_name, &iv, &tag, &data, &request_sig, &requestor_cert) == 1);
    free_charbuf(&request);
    request_type = REQ_UNK;
  }

  //Building of the json request and most combinations
  json_enc = cJSON_CreateObject();
  json_dec = cJSON_CreateObject();
  json_enc_signed = cJSON_CreateObject();
  json_dec_signed = cJSON_CreateObject();
  cJSON_AddItemToObject(json_enc, "request_type", cJSON_CreateNumber(1));
  cJSON_AddItemToObject(json_dec, "request_type", cJSON_CreateNumber(2));
  cJSON_AddItemToObject(json_enc_signed, "request_type", cJSON_CreateNumber(3));
  cJSON_AddItemToObject(json_dec_signed, "request_type", cJSON_CreateNumber(4));

  tmp = cJSON_PrintUnformatted(json_enc);
  request = new_charbuf(strlen(tmp));
  memcpy(request.chars, tmp, request.len);
  free(tmp);
  CU_ASSERT(request_decoder(request, &request_type, &key_id, &cipher_name, &iv, &tag, &data, &request_sig, &requestor_cert) == 1);
  free_charbuf(&request);
  request_type = REQ_UNK;

  tmp = cJSON_PrintUnformatted(json_dec);
  request = new_charbuf(strlen(tmp));
  memcpy(request.chars, tmp, request.len);
  free(tmp);
  CU_ASSERT(request_decoder(request, &request_type, &key_id, &cipher_name, &iv, &tag, &data, &request_sig, &requestor_cert) == 1);
  free_charbuf(&request);
  request_type = REQ_UNK;

  tmp = cJSON_PrintUnformatted(json_enc_signed);
  request = new_charbuf(strlen(tmp));
  memcpy(request.chars, tmp, request.len);
  free(tmp);
  CU_ASSERT(request_decoder(request, &request_type, &key_id, &cipher_name, &iv, &tag, &data, &request_sig, &requestor_cert) == 1);
  CU_ASSERT(request_type = REQ_ENC_SIGNED);
  free_charbuf(&request);
  request_type = REQ_UNK;

  tmp = cJSON_PrintUnformatted(json_dec_signed);
  request = new_charbuf(strlen(tmp));
  memcpy(request.chars, tmp, request.len);
  free(tmp);
  CU_ASSERT(request_decoder(request, &request_type, &key_id, &cipher_name, &iv, &tag, &data, &request_sig, &requestor_cert) == 1);
  CU_ASSERT(request_type == REQ_DEC_SIGNED);
  free_charbuf(&request);
  request_type = REQ_UNK;

  
       

  for (int i = 0; i < 6; i++)
  {
    cJSON_AddItemToObject(json_enc, "key_id", cJSON_CreateString(json_key_id[i]));
    cJSON_AddItemToObject(json_dec, "key_id", cJSON_CreateString(json_key_id[i]));
    cJSON_AddItemToObject(json_enc, "data", cJSON_CreateString(enc_data[i]));
    cJSON_AddItemToObject(json_dec, "data", cJSON_CreateString(dec_data[i]));
    cJSON_AddItemToObject(json_dec, "iv", cJSON_CreateString(dec_data[i]));
    cJSON_AddItemToObject(json_dec, "tag", cJSON_CreateString(dec_data[i]));
    cJSON_AddItemToObject(json_enc, "cipher", cJSON_CreateString(cipher_name_str));
    cJSON_AddItemToObject(json_dec, "cipher", cJSON_CreateString(cipher_name_str));


    cJSON_AddItemToObject(json_enc_signed, "key_id", cJSON_CreateString(json_key_id[i]));
    cJSON_AddItemToObject(json_dec_signed, "key_id", cJSON_CreateString(json_key_id[i]));
    cJSON_AddItemToObject(json_enc_signed, "data", cJSON_CreateString(enc_data[i]));
    cJSON_AddItemToObject(json_dec_signed, "data", cJSON_CreateString(dec_data[i]));
    cJSON_AddItemToObject(json_dec_signed, "iv", cJSON_CreateString(dec_data[i]));
    cJSON_AddItemToObject(json_dec_signed, "tag", cJSON_CreateString(dec_data[i]));
    cJSON_AddItemToObject(json_enc_signed, "cipher", cJSON_CreateString(cipher_name_str));
    cJSON_AddItemToObject(json_dec_signed, "cipher", cJSON_CreateString(cipher_name_str));
    
    cJSON_AddItemToObject(json_enc_signed, "request_sig", cJSON_CreateString("ValueEncrypt\n"));
    cJSON_AddItemToObject(json_enc_signed, "requestor_cert", cJSON_CreateString("ValueEncrypt2\n"));
    cJSON_AddItemToObject(json_dec_signed, "request_sig", cJSON_CreateString("ValueEncrypt\n"));
    cJSON_AddItemToObject(json_dec_signed, "requestor_cert", cJSON_CreateString("ValueEncrypt2\n"));
    cJSON_AddItemToObject(json_enc_signed, "cipher", cJSON_CreateString(cipher_name_str));
    cJSON_AddItemToObject(json_dec_signed, "cipher", cJSON_CreateString(cipher_name_str));

    
    
    //Creating the request charbuf for the JSON then testing request_decoder for encryption
    tmp = cJSON_PrintUnformatted(json_enc);
    request = new_charbuf(strlen(tmp));
    memcpy(request.chars, tmp, request.len);
    free(tmp);
    CU_ASSERT(request_decoder(request, &request_type, &key_id, &cipher_name, &iv, &tag, &data, &request_sig, &requestor_cert) == 0);
    CU_ASSERT(request_type == REQ_ENC);
    CU_ASSERT(key_id.len == json_key_id_len);
    CU_ASSERT(memcmp(key_id.chars, json_key_id[i], key_id.len) == 0);

    charbuf raw_data;
    decodeBase64Data((unsigned char*)enc_data[i], enc_data_len[i], &(raw_data.chars), &(raw_data.len));
    CU_ASSERT(data.len == raw_data.len);
    CU_ASSERT(memcmp(data.chars, raw_data.chars, data.len) == 0);
    free_charbuf(&raw_data);
    CU_ASSERT(cipher_name.len == strlen(cipher_name_str));
    CU_ASSERT(memcmp(cipher_name.chars, cipher_name_str, cipher_name.len) == 0);
    
    // An encrypt request should never populate iv or tag.
    CU_ASSERT(iv.len == 0);
    CU_ASSERT(tag.len == 0);
    
    free_charbuf(&request);
    request_type = REQ_UNK;
    free_charbuf(&key_id);
    free_charbuf(&data);
    free_charbuf(&cipher_name);
    
    //Creating the request charbuf for the JSON then testing request_decoder for decryption
    tmp = cJSON_PrintUnformatted(json_dec);
    request = new_charbuf(strlen(tmp));
    memcpy(request.chars, tmp, request.len);
    free(tmp);
    CU_ASSERT(request_decoder(request, &request_type, &key_id, &cipher_name, &iv, &tag, &data, &request_sig, &requestor_cert) == 0);
    CU_ASSERT(request_type == REQ_DEC);
    CU_ASSERT(key_id.len == json_key_id_len);
    CU_ASSERT(memcmp(key_id.chars, json_key_id[i], key_id.len) == 0);
    decodeBase64Data((unsigned char*)dec_data[i], dec_data_len[i], &(raw_data.chars), &(raw_data.len));
    CU_ASSERT(data.len == raw_data.len);
    CU_ASSERT(memcmp(data.chars, raw_data.chars, data.len) == 0);

    CU_ASSERT(iv.len == raw_data.len);
    CU_ASSERT(memcmp(iv.chars, raw_data.chars, iv.len) == 0);
    CU_ASSERT(memcmp(tag.chars, dec_data[i], tag.len) == 0);
    CU_ASSERT(cipher_name.len == strlen(cipher_name_str));
    CU_ASSERT(memcmp(cipher_name.chars, cipher_name_str, cipher_name.len) == 0);
    
    free_charbuf(&request);
    free_charbuf(&iv);
    free_charbuf(&tag);
    request_type = REQ_UNK;
    free_charbuf(&key_id);
    free_charbuf(&data);


    tmp = cJSON_PrintUnformatted(json_enc_signed);
    request = new_charbuf(strlen(tmp));
    memcpy(request.chars, tmp, request.len);
    free(tmp);
    CU_ASSERT(request_decoder(request, &request_type, &key_id, &cipher_name, &iv, &tag, &data, &request_sig, &requestor_cert) == 0);
    CU_ASSERT(request_type = REQ_ENC_SIGNED);
    free_charbuf(&request);
    free_charbuf(&iv);
    free_charbuf(&tag);
    free_charbuf(&key_id);
    free_charbuf(&data);
    free_charbuf(&request_sig);
    free_charbuf(&requestor_cert);
    request_type = REQ_UNK;


    tmp = cJSON_PrintUnformatted(json_dec_signed);
    request = new_charbuf(strlen(tmp));
    memcpy(request.chars, tmp, request.len);
    free(tmp);
    CU_ASSERT(request_decoder(request, &request_type, &key_id, &cipher_name, &iv, &tag, &data, &request_sig, &requestor_cert) == 0);
    CU_ASSERT(request_type == REQ_DEC_SIGNED);
    free_charbuf(&request);
    free_charbuf(&iv);
    free_charbuf(&tag);
    free_charbuf(&key_id);
    free_charbuf(&data);
    free_charbuf(&request_sig);
    free_charbuf(&requestor_cert);
    request_type = REQ_UNK;
    

    //Free the cJSON Objects to allow the addition of the next Object per the loop
    cJSON_DeleteItemFromObject(json_dec, "data");
    cJSON_DeleteItemFromObject(json_enc, "data");
    cJSON_DeleteItemFromObject(json_enc, "key_id");
    cJSON_DeleteItemFromObject(json_dec, "key_id");
    cJSON_DeleteItemFromObject(json_dec, "iv");
    cJSON_DeleteItemFromObject(json_dec, "tag");
    cJSON_DeleteItemFromObject(json_enc, "cipher");
    cJSON_DeleteItemFromObject(json_dec, "cipher");
    cJSON_DeleteItemFromObject(json_dec_signed, "data");
    cJSON_DeleteItemFromObject(json_enc_signed, "data");
    cJSON_DeleteItemFromObject(json_enc_signed, "key_id");
    cJSON_DeleteItemFromObject(json_dec_signed, "key_id");
    cJSON_DeleteItemFromObject(json_dec_signed, "iv");
    cJSON_DeleteItemFromObject(json_dec_signed, "tag");
    cJSON_DeleteItemFromObject(json_enc_signed, "request_sig");
    cJSON_DeleteItemFromObject(json_enc_signed, "requestor_cert");
    cJSON_DeleteItemFromObject(json_dec_signed, "request_sig");
    cJSON_DeleteItemFromObject(json_dec_signed, "requestor_cert");
    cJSON_DeleteItemFromObject(json_enc_signed, "cipher");
    cJSON_DeleteItemFromObject(json_dec_signed, "cipher");
    
  }

  cJSON_Delete(json_enc);
  cJSON_Delete(json_dec);
  cJSON_Delete(json_enc_signed);
  cJSON_Delete(json_dec_signed);
}

void test_message_encoder(void)
{
  charbuf key_id;
  charbuf data;
  charbuf request_sig;
  charbuf requestor_cert;
  charbuf iv;
  charbuf tag;
  charbuf message;
  charbuf cipher_name;

  const char* cipher_name_str = "cipher_name";
  
  const char *test[5] = { "file:/test/key1.txt", "test/key1.txt", "file", "anything", "" };
  const char *valid_dec_message[5] =
    { "{\"key_id\":\"file:/test/key1.txt\",\"cipher\":\"cipher_name\",\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\"}",
      "{\"key_id\":\"test/key1.txt\",\"cipher\":\"cipher_name\",\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\"}",   
      "{\"key_id\":\"file\",\"cipher\":\"cipher_name\",\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\"}",
      "{\"key_id\":\"anything\",\"cipher\":\"cipher_name\",\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\"}",
      "{\"key_id\":\"\",\"cipher\":\"cipher_name\",\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\"}"
  };
  const char *valid_enc_message[5] =
    { "{\"key_id\":\"file:/test/key1.txt\",\"cipher\":\"cipher_name\",\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"tag\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"iv\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\"}",
    "{\"key_id\":\"test/key1.txt\",\"cipher\":\"cipher_name\",\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"tag\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"iv\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\"}",
    "{\"key_id\":\"file\",\"cipher\":\"cipher_name\",\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"tag\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"iv\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\"}",
    "{\"key_id\":\"anything\",\"cipher\":\"cipher_name\",\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"tag\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"iv\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\"}",
    "{\"key_id\":\"\",\"cipher\":\"cipher_name\",\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"tag\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"iv\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\"}"
  };

  //Start Message Encoder Test
  pelz_log(LOG_DEBUG, "Start Message Encoder Test");

  data = new_charbuf(57);
  iv = new_charbuf(57);
  tag = new_charbuf(57);
  cipher_name = new_charbuf(strlen(cipher_name_str));
  memcpy(cipher_name.chars, cipher_name_str, cipher_name.len);
  
  memcpy(data.chars, "SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\n", data.len);
  memcpy(iv.chars, data.chars, data.len);
  memcpy(tag.chars, data.chars, data.len);
  
  key_id = new_charbuf(strlen(test[0]));
  memcpy(key_id.chars, test[0], key_id.len);

  request_sig = new_charbuf(11);
  memcpy(request_sig.chars, "HelloWorld\n", request_sig.len);
  requestor_cert = new_charbuf(11);
  memcpy(requestor_cert.chars, "PelzProject\n", requestor_cert.len);

  // Testing a request without signatures/certificates (This will be removed after they are required)
  free_charbuf(&request_sig);
  free_charbuf(&requestor_cert);
  CU_ASSERT(message_encoder(REQ_ENC, key_id, cipher_name, iv, tag, data, &message) == 0);

  free_charbuf(&key_id);

  // Testing unsigned responses
  for (int i = 0; i < 5; i++)
  {
    key_id = new_charbuf(strlen(test[i]));
    memcpy(key_id.chars, test[i], key_id.len);
    CU_ASSERT(message_encoder(REQ_ENC, key_id, cipher_name, iv, tag, data, &message) == 0);
    CU_ASSERT(memcmp(message.chars, valid_enc_message[i], message.len) == 0);
    free_charbuf(&message);
    CU_ASSERT(message_encoder(REQ_DEC, key_id, cipher_name, iv, tag, data, &message) == 0);
    CU_ASSERT(memcmp(message.chars, valid_dec_message[i], message.len) == 0);
    free_charbuf(&message);
    free_charbuf(&key_id);
  }
  free_charbuf(&cipher_name);

  // TODO: Test signed responses
  request_sig = new_charbuf(11);
  memcpy(request_sig.chars, "HelloWorld\n", request_sig.len);
  requestor_cert = new_charbuf(11);
  memcpy(requestor_cert.chars, "PelzProject\n", requestor_cert.len);
  free_charbuf(&request_sig);
  free_charbuf(&requestor_cert);

  free_charbuf(&data);
}

void test_error_message_encoder(void)
{
  pelz_log(LOG_DEBUG, "Test err msg");
  const char *err_msg[5] = {
    "Missing Data", "missing data", "akdifid", "Error", "Any message"
  };
  charbuf message;

  for (int i = 0; i < 5; i++)
  {
    CU_ASSERT(error_message_encoder(&message, err_msg[i]) == 0);
    pelz_log(LOG_DEBUG, "Error Message: %.*s", message.len, message.chars);
    free_charbuf(&message);
  }
}
