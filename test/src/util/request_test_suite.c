/*
 * request_test_suite.c
 */

#include "request_test_suite.h"
#include "test_helper_functions.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cjson/cJSON.h>

#include <charbuf.h>
#include <pelz_log.h>
#include <common_table.h>
#include <pelz_request_handler.h>

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "test_enclave_u.h"

// Adds all request handler tests to main test runner.
int request_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test Pelz Request Handler", test_request))
  {
    return (1);
  }
  return (0);
}

void test_request(void)
{
  TableResponseStatus ret;
  RequestResponseStatus status;
  RequestType request_type = REQ_UNK;
  charbuf tmp;
  charbuf key;
  charbuf data_in;
  charbuf data;
  charbuf output;
  const char *prefix = "file:";
  const char *valid_id[3] = { "/test/data/key1.txt", "/test/data/key2.txt", "/test/data/key3.txt" };
  const char *tmp_id[2] = { "/test/data/key7.txt", "/test/data/key1txt" };
  const char *key_str[3] = { "KIENJCDNHVIJERLMALIDFEKIUFDALJFG", "KALIENGVBIZSAIXKDNRUEHFMDDUHVKAN", "HVIJERLMALIDFKDN" };

  //Initial data_in values
  data_in = new_charbuf(32);
  memcpy(data_in.chars, "abcdefghijklmnopqrstuvwxyz012345", data_in.len);

  pelz_log(LOG_DEBUG, "Test Request Function Start");

  //KEK not loaded so function should return KEK_NOT_LOADED
  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  request_type = REQ_ENC;
  pelz_request_handler(eid, &status, request_type, tmp, data_in, &output);
  CU_ASSERT(status == KEK_NOT_LOADED);
  request_type = REQ_DEC;
  pelz_request_handler(eid, &status, request_type, tmp, data_in, &output);
  CU_ASSERT(status == KEK_NOT_LOADED);
  free_charbuf(&tmp);
  request_type = REQ_UNK;

  //Initial check if request encrypts and decrypts keys
  for (int i = 0; i < 3; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    key = new_charbuf(strlen(key_str[i]));
    memcpy(key.chars, key_str[i], key.len);
    key_table_add_key(eid, &ret, tmp, key);
    CU_ASSERT(ret == OK);
    secure_free_charbuf(&key);
    request_type = REQ_ENC;
    pelz_request_handler(eid, &status, request_type, tmp, data_in, &output);
    CU_ASSERT(status == REQUEST_OK);
    request_type = REQ_DEC;
    data = copy_chars_from_charbuf(output, 0);
    secure_free_charbuf(&output);
    pelz_request_handler(eid, &status, request_type, tmp, data, &output);
    CU_ASSERT(status == REQUEST_OK);
    CU_ASSERT(cmp_charbuf(output, data_in) == 0);
    free_charbuf(&tmp);
    secure_free_charbuf(&data);
    secure_free_charbuf(&output);
  }

  //Check that non-valid file does not load key
  tmp = copy_CWD_to_id(prefix, tmp_id[0]);
  pelz_request_handler(eid, &status, REQ_ENC, tmp, data_in, &output);
  CU_ASSERT(status == KEK_NOT_LOADED);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, tmp_id[1]);
  pelz_request_handler(eid, &status, REQ_ENC, tmp, data_in, &output);
  CU_ASSERT(status == KEK_NOT_LOADED);
  free_charbuf(&tmp);

  //Check that non-valid request type returns correct error status
  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  request_type = REQ_UNK;
  pelz_request_handler(eid, &status, request_type, tmp, data_in, &output);
  CU_ASSERT(status == REQUEST_TYPE_ERROR);
  free_charbuf(&tmp);

  //Check that non-valid encyption key returns correct error status
  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  request_type = REQ_ENC;
  data = new_charbuf(8);
  memcpy(data.chars, "abcdefgh", data.len);
  pelz_request_handler(eid, &status, request_type, tmp, data, &output);
  CU_ASSERT(status == KEY_OR_DATA_ERROR);
  secure_free_charbuf(&data);

  data = new_charbuf(30);
  memcpy(data.chars, "abcdefghijklmnopqrstuvwxyz0123", data.len);
  pelz_request_handler(eid, &status, request_type, tmp, data, &output);
  CU_ASSERT(status == KEY_OR_DATA_ERROR);
  secure_free_charbuf(&data);
  free_charbuf(&tmp);

  //Check that non-valid decryption key returns correct error status
  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  request_type = REQ_DEC;
  data = new_charbuf(8);
  memcpy(data.chars, "abcdefgh", data.len);
  pelz_request_handler(eid, &status, request_type, tmp, data, &output);
  CU_ASSERT(status == KEY_OR_DATA_ERROR);
  secure_free_charbuf(&data);

  data = new_charbuf(30);
  memcpy(data.chars, "abcdefghijklmnopqrstuvwxyz0123", data.len);
  pelz_request_handler(eid, &status, request_type, tmp, data, &output);
  CU_ASSERT(status == KEY_OR_DATA_ERROR);
  secure_free_charbuf(&data);
  free_charbuf(&tmp);

  table_destroy(eid, &ret, KEY);
  CU_ASSERT(ret == OK);
  pelz_log(LOG_DEBUG, "Test Request Function Finish");
}
