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

#include "sgx_urts.h"
#include "sgx_seal_unseal_impl.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"

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
  TableResponseStatus ret;

  pelz_log(LOG_DEBUG, "Test Key Table Destroy Function Start");
  table_destroy(eid, &ret, KEY);
  CU_ASSERT(ret == OK);
  table_destroy(eid, &ret, SERVER);
  CU_ASSERT(ret == OK);
  table_destroy(eid, &ret, TEST);
  CU_ASSERT(ret == ERR);
  pelz_log(LOG_DEBUG, "Test Key Table Destroy Function Finish");
}

void test_table_add(void)
{
  TableResponseStatus ret;
  charbuf tmp;
  charbuf key;
  uint8_t *data = NULL;
  size_t data_len = 0;
  uint64_t handle;
  const char *prefix = "file:";
  const char *valid_id[3] = { "/test/key1.txt", "client_cert_test.der.nkl", "client_priv_test.der.nkl" };
  const char *key1 = "KIENJCDNHVIJERLMALIDFEKIUFDALJFG";

  pelz_log(LOG_DEBUG, "Test Request Function Start");

  //Testing the key table add
  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  key_table_add(eid, &ret, tmp, &key);
  CU_ASSERT(ret == OK);
  CU_ASSERT(memcmp(key.chars, key1, key.len) == 0);
  secure_free_charbuf(&key);
  free_charbuf(&tmp);

  //Testing the server table add
  server_table_add(eid, &ret, handle);
  CU_ASSERT(ret == RET_FAIL);

  tmp = copy_CWD_to_id(prefix, valid_id[1]);
  CU_ASSERT(read_bytes_from_file((char *) tmp.chars, &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);
  free_charbuf(&tmp);

  server_table_add(eid, &ret, handle);
  CU_ASSERT(ret == OK);

  //Testing the private pkey add
  private_pkey_init(eid, &ret);
  CU_ASSERT(ret == OK);
  private_pkey_add(eid, &ret, handle);
  CU_ASSERT(ret == RET_FAIL);

  tmp = copy_CWD_to_id(prefix, valid_id[2]);
  CU_ASSERT(read_bytes_from_file((char *) tmp.chars, &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);
  free_charbuf(&tmp);

  private_pkey_add(eid, &ret, handle);
  CU_ASSERT(ret == OK);
  private_pkey_free(eid, &ret);
  CU_ASSERT(ret == OK);

  table_destroy(eid, &ret, KEY);
  CU_ASSERT(ret == OK);
  table_destroy(eid, &ret, SERVER);
  CU_ASSERT(ret == OK);
  pelz_log(LOG_DEBUG, "Test Request Function Finish");
}

void test_table_lookup(void)
{
  TableResponseStatus ret;
  charbuf tmp;
  charbuf key;
  uint8_t *data = NULL;
  size_t data_len = 0;
  uint64_t handle;
  int index = 0;
  const char *prefix = "file:";

  const char *valid_id[8] = {
    "/test/key1.txt", "/test/key2.txt", "/test/key3.txt", "/test/key4.txt", "/test/key5.txt", "/test/key6.txt",
    "client_cert_test.der.nkl" "server_cert_test.der.nkl"
  };
  const char *tmp_id[2] = { "/test/key.txt", "/test/key1txt" };

  pelz_log(LOG_DEBUG, "Test Table Look-up Function Start");
  //Initial load of keys into the key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    key_table_add(eid, &ret, tmp, &key);
    CU_ASSERT(ret == OK);
    secure_free_charbuf(&key);
    free_charbuf(&tmp);
  }

  //Initial load of certs into the server table
  tmp = copy_CWD_to_id(prefix, valid_id[6]);
  CU_ASSERT(read_bytes_from_file((char *) tmp.chars, &data, &data_len) == 0);
  free_charbuf(&tmp);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);
  server_table_add(eid, &ret, handle);
  CU_ASSERT(ret == OK);

  tmp = copy_CWD_to_id(prefix, valid_id[7]);
  CU_ASSERT(read_bytes_from_file((char *) tmp.chars, &data, &data_len) == 0);
  free_charbuf(&tmp);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);
  server_table_add(eid, &ret, handle);
  CU_ASSERT(ret == OK);

  //Testing the look-up function for key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    table_lookup(eid, &ret, KEY, tmp, &index);
    CU_ASSERT(ret == OK);
    CU_ASSERT(index == i);
    free_charbuf(&tmp);
    index = 0;
  }

  //Testing id not found for key table
  tmp = copy_CWD_to_id(prefix, tmp_id[0]);
  table_lookup(eid, &ret, KEY, tmp, &index);
  CU_ASSERT(ret == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, tmp_id[1]);
  table_lookup(eid, &ret, KEY, tmp, &index);
  CU_ASSERT(ret == NO_MATCH);
  free_charbuf(&tmp);

  //Testing the look-up function for server table
  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  table_lookup(eid, &ret, SERVER, tmp, &index);
  CU_ASSERT(ret == OK);
  CU_ASSERT(index == 0);
  free_charbuf(&tmp);
  index = 0;

  tmp = new_charbuf(strlen("TestServer"));
  memcpy(tmp.chars, "TestServer", tmp.len);
  table_lookup(eid, &ret, SERVER, tmp, &index);
  CU_ASSERT(ret == OK);
  CU_ASSERT(index == 1);
  free_charbuf(&tmp);
  index = 0;

  //Testing id not found for server table
  tmp = new_charbuf(strlen("TestTestTest"));
  memcpy(tmp.chars, "TestTestTest", tmp.len);
  table_lookup(eid, &ret, SERVER, tmp, &index);
  CU_ASSERT(ret == NO_MATCH);
  free_charbuf(&tmp);
  table_destroy(eid, &ret, KEY);
  CU_ASSERT(ret == OK);
  table_destroy(eid, &ret, SERVER);
  CU_ASSERT(ret == OK);
  pelz_log(LOG_DEBUG, "Test Table Look-up Function Finish");
}

void test_table_delete(void)
{
  TableResponseStatus ret;
  charbuf tmp;
  charbuf key;
  uint8_t *data = NULL;
  size_t data_len = 0;
  uint64_t handle;
  const char *prefix = "file:";

  const char *valid_id[6] = {
    "/test/key1.txt", "/test/key2.txt", "/test/key3.txt", "/test/key4.txt", "/test/key5.txt", "/test/key6.txt"
  };
  const char *tmp_id[2] = {
    "/test/key.txt", "/test/key1txt"
  };
  pelz_log(LOG_DEBUG, "Test  Table Delete Function Start");
  //Initial load of keys into the key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    key_table_add(eid, &ret, tmp, &key);
    CU_ASSERT(ret == OK);
    free_charbuf(&tmp);
    secure_free_charbuf(&key);
  }

  //Initial load of certs into the server table
  tmp = copy_CWD_to_id(prefix, valid_id[6]);
  CU_ASSERT(read_bytes_from_file((char *) tmp.chars, &data, &data_len) == 0);
  free_charbuf(&tmp);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);
  server_table_add(eid, &ret, handle);
  CU_ASSERT(ret == OK);
  tmp = copy_CWD_to_id(prefix, valid_id[7]);
  CU_ASSERT(read_bytes_from_file((char *) tmp.chars, &data, &data_len) == 0);
  free_charbuf(&tmp);
  CU_ASSERT(kmyth_sgx_unseal_nkl(eid, data, data_len, &handle) == 0);
  free(data);
  server_table_add(eid, &ret, handle);
  CU_ASSERT(ret == OK);
  //Testing the delete function for key table
  tmp = copy_CWD_to_id(prefix, valid_id[3]);
  table_delete(eid, &ret, KEY, tmp);
  CU_ASSERT(ret == OK);
  free_charbuf(&tmp);
  tmp = copy_CWD_to_id(prefix, valid_id[5]);
  table_delete(eid, &ret, KEY, tmp);
  CU_ASSERT(ret == OK);
  free_charbuf(&tmp);
  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  table_delete(eid, &ret, KEY, tmp);
  CU_ASSERT(ret == OK);
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
  //Testing the delete function for server table
  tmp = new_charbuf(strlen("TestTestTest"));
  memcpy(tmp.chars, "TestTestTest", tmp.len);
  table_delete(eid, &ret, SERVER, tmp);
  CU_ASSERT(ret == NO_MATCH);
  free_charbuf(&tmp);
  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  table_delete(eid, &ret, SERVER, tmp);
  CU_ASSERT(ret == OK);
  free_charbuf(&tmp);
  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  table_delete(eid, &ret, SERVER, tmp);
  CU_ASSERT(ret == NO_MATCH);
  free_charbuf(&tmp);
  tmp = new_charbuf(strlen("TestServer"));
  memcpy(tmp.chars, "TestServer", tmp.len);
  table_delete(eid, &ret, SERVER, tmp);
  CU_ASSERT(ret == OK);
  free_charbuf(&tmp);
  table_destroy(eid, &ret, KEY);
  CU_ASSERT(ret == OK);
  table_destroy(eid, &ret, SERVER);
  CU_ASSERT(ret == OK);
  pelz_log(LOG_DEBUG, "Test Table Delete Function Finish");
}
