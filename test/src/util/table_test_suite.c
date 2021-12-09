/*
 * table_test_suite.c
 */

#include "table_test_suite.h"
#include "test_helper_functions.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cjson/cJSON.h>
#include <kmyth/kmyth.h>
#include <kmyth/file_io.h>

#include <charbuf.h>
#include <pelz_log.h>
#include <common_table.h>

#include "pelz_enclave_t.h"

// Adds all table tests to main test runner.
int table_suite_add_tests(CU_pSuite suite)
{

  if (NULL == CU_add_test(suite, "Test Table Destruction", test_table_destroy))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Table Addition", test_table_add))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Table Look-up", test_table_lookup))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Table Deletation", test_table_delete))
  {
    return (1);
  }
  return (0);
}

void test_table_destroy(void)
{
  pelz_log(LOG_DEBUG, "Test Key Table Destroy Function Start");
  CU_ASSERT(table_destroy(KEY) == OK);
  CU_ASSERT(table_destroy(SERVER) == OK);
  CU_ASSERT(table_destroy(TEST) == ERR);
  pelz_log(LOG_DEBUG, "Test Key Table Destroy Function Finish");
}

void test_table_add(void)
{
  TableResponseStatus status;
  charbuf tmp;
  charbuf key;
  uint8_t *data = NULL;
  size_t data_len = 0;
  uint64_t handle;
  const char *prefix = "file:";
  const char *valid_id[3] = { "/test/key1.txt", "test/client_cert_test.der.nkl", "test/client_priv_test.der.nkl" };

  pelz_log(LOG_DEBUG, "Test Table Add Function Start");

  //Testing the key table add
  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  CU_ASSERT(key_table_add(tmp, &key) == OK);
  free_charbuf(&tmp);
  secure_free_charbuf(&key);
  pelz_log(LOG_DEBUG, "Key Table Add Successful");

  //Testing the server table add
  CU_ASSERT(server_table_add(handle) == RET_FAIL);

  CU_ASSERT(read_bytes_from_file((char *) valid_id[1], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);

  server_table_add(eid, &status, handle);
  CU_ASSERT(status == OK);
  pelz_log(LOG_DEBUG, "Server Table Add Successful");

  //Testing the private pkey add
  private_pkey_init(eid, &status);
  CU_ASSERT(status == OK);
  private_pkey_add(eid, &status, handle);
  CU_ASSERT(status == RET_FAIL);

  CU_ASSERT(read_bytes_from_file((char *) valid_id[2], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);

  private_pkey_add(eid, &status, handle);
  pelz_log(LOG_DEBUG, "private_pkey_add return: %lu", status);
  CU_ASSERT(status == OK);
  private_pkey_free(eid, &status);
  CU_ASSERT(status == OK);
  pelz_log(LOG_DEBUG, "Private Key Add Successful");

  table_destroy(eid, &status, KEY);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, SERVER);
  CU_ASSERT(status == OK);
  pelz_log(LOG_DEBUG, "Test Table Add Function Finish");
}

void test_table_lookup(void)
{
  TableResponseStatus status;
  charbuf tmp;
  charbuf key;
  uint8_t *data = NULL;
  size_t data_len = 0;
  uint64_t handle;
  int index = 0;
  const char *prefix = "file:";

  const char *valid_id[8] = {
    "/test/key1.txt", "/test/key2.txt", "/test/key3.txt", "/test/key4.txt", "/test/key5.txt", "/test/key6.txt",
    "test/client_cert_test.der.nkl" "test/server_cert_test.der.nkl"
  };
  const char *tmp_id[2] = { "/test/key.txt", "/test/key1txt" };

  pelz_log(LOG_DEBUG, "Test Table Look-up Function Start");
  //Initial load of keys into the key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    status = key_table_add(tmp, &key);
    CU_ASSERT(status == OK);
    free_charbuf(&tmp);
    secure_free_charbuf(&key);
  }

  //Initial load of certs into the server table
  CU_ASSERT(read_bytes_from_file((char *) valid_id[6], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);
  server_table_add(eid, &status, handle);
  CU_ASSERT(status == OK);

  CU_ASSERT(read_bytes_from_file((char *) valid_id[7], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);
  server_table_add(eid, &status, handle);
  CU_ASSERT(status == OK);

  //Testing the look-up function for key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    status = table_lookup(KEY, tmp, &index);
    CU_ASSERT(status == OK);
    CU_ASSERT(index == i);
    free_charbuf(&tmp);
    index = 0;
  }

  //Testing id not found for key table
  tmp = copy_CWD_to_id(prefix, tmp_id[0]);
  status = table_lookup(KEY, tmp, &index);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, tmp_id[1]);
  status = table_lookup(KEY, tmp, &index);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  //Testing the look-up function for server table
  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  status = table_lookup(SERVER, tmp, &index);
  CU_ASSERT(status == OK);
  CU_ASSERT(index == 0);
  free_charbuf(&tmp);
  index = 0;

  tmp = new_charbuf(strlen("TestServer"));
  memcpy(tmp.chars, "TestServer", tmp.len);
  status = table_lookup(SERVER, tmp, &index);
  CU_ASSERT(status == OK);
  CU_ASSERT(index == 1);
  free_charbuf(&tmp);
  index = 0;

  //Testing id not found for server table
  tmp = new_charbuf(strlen("TestTestTest"));
  memcpy(tmp.chars, "TestTestTest", tmp.len);
  status = table_lookup(SERVER, tmp, &index);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  table_destroy(eid, &status, KEY);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, SERVER);
  CU_ASSERT(status == OK);
  pelz_log(LOG_DEBUG, "Test Table Look-up Function Finish");
}

void test_table_delete(void)
{
  TableResponseStatus status;
  charbuf tmp;
  charbuf key;
  uint8_t *data = NULL;
  size_t data_len = 0;
  uint64_t handle;
  const char *prefix = "file:";

  const char *valid_id[8] = {
    "/test/key1.txt", "/test/key2.txt", "/test/key3.txt", "/test/key4.txt", "/test/key5.txt", "/test/key6.txt",
    "test/client_cert_test.der.nkl" "test/server_cert_test.der.nkl"
  };
  const char *tmp_id[2] = {
    "/test/key.txt", "/test/key1txt"
  };
  pelz_log(LOG_DEBUG, "Test  Table Delete Function Start");
  //Initial load of keys into the key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    status = key_table_add(tmp, &key);
    CU_ASSERT(status == OK);
    free_charbuf(&tmp);
    secure_free_charbuf(&key);
  }

  //Initial load of certs into the server table
  CU_ASSERT(read_bytes_from_file((char *) valid_id[6], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);
  server_table_add(eid, &status, handle);
  CU_ASSERT(status == OK);

  CU_ASSERT(read_bytes_from_file((char *) valid_id[7], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);
  server_table_add(eid, &status, handle);
  CU_ASSERT(status == OK);

  //Testing the delete function for key table
  tmp = copy_CWD_to_id(prefix, valid_id[3]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[5]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);

  //Testing that if the delete function does not find key_id then does not delete for valid files and non-valid files
  tmp = copy_CWD_to_id(prefix, tmp_id[0]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, tmp_id[1]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("adaj;ldkjidka;dfkjai"));
  memcpy(tmp.chars, "adaj;ldkjidka;dfkjai", tmp.len);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[5]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  //Testing the delete function for server table
  tmp = new_charbuf(strlen("TestTestTest"));
  memcpy(tmp.chars, "TestTestTest", tmp.len);
  table_delete(eid, &status, SERVER, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  table_delete(eid, &status, SERVER, tmp);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  table_delete(eid, &status, SERVER, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("TestServer"));
  memcpy(tmp.chars, "TestServer", tmp.len);
  table_delete(eid, &status, SERVER, tmp);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);

  table_destroy(eid, &status, KEY);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, SERVER);
  CU_ASSERT(status == OK);
  pelz_log(LOG_DEBUG, "Test Table Delete Function Finish");
}
