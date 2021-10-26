/*
 * enclave_test_suite.c
 */

#include "enclave_test_suite.h"
#include "test_helper_functions.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cjson/cJSON.h>

#include <charbuf.h>
#include <pelz_log.h>
#include <common_table.h>
#include <key_table.h>
#include <server_table.h>
#include <pelz_request_handler.h>

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"

// Adds all key table tests to main test runner.
int enclave_suite_add_tests(CU_pSuite suite)
{

  if (NULL == CU_add_test(suite, "Test Key Table Destruction", test_table_destroy))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Pelz Request Handler", test_table_request))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Pelz Request Handler and Key Table Delete", test_table_requestDelete))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Server Table Destruction", test_server_table_destroy))
  {
    return (1);
  }
  return (0);
}

void test_table_destroy(void)
{
  int ret;

  pelz_log(LOG_DEBUG, "Test Key Table Destroy Function Start");
  table_destroy(eid, &ret, KEY);
  CU_ASSERT(ret == 0);
  pelz_log(LOG_DEBUG, "Test Key Table Destroy Function Finish");
}

void test_table_request(void)
{
  RequestResponseStatus status;
  RequestType request_type = REQ_UNK;
  int ret;
  charbuf tmp;
  charbuf data_in;
  charbuf data;
  charbuf output;
  const char *prefix = "file:";
  const char *valid_id[3] = { "/test/key1.txt", "/test/key2.txt", "/test/key3.txt" };
  const char *tmp_id[2] = { "/test/key7.txt", "/test/key1txt" };

  //Initial data_in values
  data_in = new_charbuf(32);
  memcpy(data_in.chars, "abcdefghijklmnopqrstuvwxyz012345", data_in.len);

  pelz_log(LOG_DEBUG, "Test Request Function Start");

  //Initial check if request encrypts and decrypts keys
  for (int i = 0; i < 3; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    request_type = REQ_ENC;
    pelz_request_handler(eid, &status, request_type, tmp, data_in, &output);
    CU_ASSERT(status == 0);
    request_type = REQ_DEC;
    data = copy_chars_from_charbuf(output, 0);
    secure_free_charbuf(&output);
    pelz_request_handler(eid, &status, request_type, tmp, data, &output);
    CU_ASSERT(status == 0);
    CU_ASSERT(cmp_charbuf(output, data_in) == 0);
    free_charbuf(&tmp);
    secure_free_charbuf(&data);
    secure_free_charbuf(&output);
  }

  //Check that non-valid file does not load key
  tmp = copy_CWD_to_id(prefix, tmp_id[0]);
  pelz_request_handler(eid, &status, REQ_ENC, tmp, data_in, &output);
  CU_ASSERT(status == KEK_LOAD_ERROR);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, tmp_id[1]);
  pelz_request_handler(eid, &status, REQ_ENC, tmp, data_in, &output);
  CU_ASSERT(status == KEK_LOAD_ERROR);
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
  CU_ASSERT(ret == 0);
  pelz_log(LOG_DEBUG, "Test Request Function Finish");
}

void test_table_requestDelete(void)
{
  RequestResponseStatus status;
  RequestType request_type = REQ_UNK;
  int ret;
  charbuf tmp;
  charbuf data_in;
  charbuf data;
  charbuf output;
  const char *prefix = "file:";

  const char *valid_id[6] = { "/test/key1.txt", "/test/key2.txt", "/test/key3.txt",
    "/test/key4.txt", "/test/key5.txt", "/test/key6.txt"
  };
  const char *tmp_id[2] = { "/test/key.txt", "/test/key1txt" };

  //Initial data_in values
  data_in = new_charbuf(32);
  memcpy(data_in.chars, "abcdefghijklmnopqrstuvwxyz012345", data_in.len);

  pelz_log(LOG_DEBUG, "Test Request and Delete Functions Start");

  //Initial load of keys into the key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    request_type = REQ_ENC;
    pelz_request_handler(eid, &status, request_type, tmp, data_in, &output);
    CU_ASSERT(status == 0);
    request_type = REQ_DEC;
    data = copy_chars_from_charbuf(output, 0);
    secure_free_charbuf(&output);
    pelz_request_handler(eid, &status, request_type, tmp, data, &output);
    CU_ASSERT(status == 0);
    CU_ASSERT(cmp_charbuf(output, data_in) == 0);
    free_charbuf(&tmp);
    secure_free_charbuf(&data);
    secure_free_charbuf(&output);
  }

  pelz_log(LOG_DEBUG, "Initial load of keys finish and start testing of delete function");

  //Testing the delete function
  tmp = copy_CWD_to_id(prefix, valid_id[3]);
  table_delete(eid, &ret, KEY, tmp);
  CU_ASSERT(ret == 0);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[5]);
  table_delete(eid, &ret, KEY, tmp);
  CU_ASSERT(ret == 0);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  table_delete(eid, &ret, KEY, tmp);
  CU_ASSERT(ret == 0);
  free_charbuf(&tmp);

  //Testing that if the delete function does not find key_id then does not delete for valid files and non-valid files
  tmp = copy_CWD_to_id(prefix, tmp_id[0]);
  table_delete(eid, &ret, KEY, tmp);
  CU_ASSERT(ret == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, tmp_id[1]);
  table_delete(eid, &ret, KEY, tmp);
  CU_ASSERT(ret == NO_MATCH);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("adaj;ldkjidka;dfkjai"));
  memcpy(tmp.chars, "adaj;ldkjidka;dfkjai", tmp.len);
  table_delete(eid, &ret, KEY, tmp);
  CU_ASSERT(ret == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[5]);
  table_delete(eid, &ret, KEY, tmp);
  CU_ASSERT(ret == NO_MATCH);
  free_charbuf(&tmp);

  //Request will reload keys into the key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    request_type = REQ_ENC;
    pelz_request_handler(eid, &status, request_type, tmp, data_in, &output);
    CU_ASSERT(status == 0);
    request_type = REQ_DEC;
    data = copy_chars_from_charbuf(output, 0);
    secure_free_charbuf(&output);
    pelz_request_handler(eid, &status, request_type, tmp, data, &output);
    CU_ASSERT(status == 0);
    CU_ASSERT(cmp_charbuf(output, data_in) == 0);
    free_charbuf(&tmp);
    secure_free_charbuf(&data);
    secure_free_charbuf(&output);
  }

  table_destroy(eid, &ret, KEY);
  CU_ASSERT(ret == 0);
  pelz_log(LOG_DEBUG, "Test Request and Delete Functions Finish");
}

void test_server_table_destroy(void)
{
  int ret;

  pelz_log(LOG_DEBUG, "Test Server Table Destroy Function Start");
  table_destroy(eid, &ret, SERVER);
  CU_ASSERT(ret == 0);
  pelz_log(LOG_DEBUG, "Test Server Table Destroy Function Finish");
}
