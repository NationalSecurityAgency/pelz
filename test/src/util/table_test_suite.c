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
  charbuf tmp;
  charbuf key;
  uint8_t *data = NULL;
  size_t data_len = 0;
  uint64_t handle;
  const char *prefix = "file:";
  const char *valid_id[3] = { "/test/key1.txt", "test/client_cert_test.der.nkl", "test/client_priv_test.der.nkl" };
  const char *key_str = "KIENJCDNHVIJERLMALIDFEKIUFDALJFG";

  pelz_log(LOG_DEBUG, "Test Table Add Function Start");

  //Testing the key table add
  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  key = new_charbuf(strlen(key_str));
  memcpy(key.chars, key_str, key.len);
  CU_ASSERT(key_table_add_key(tmp, key) == OK);
  free_charbuf(&tmp);
  secure_free_charbuf(&key);
  pelz_log(LOG_DEBUG, "Key Table Add Successful");

  //Testing the server table add
  CU_ASSERT(server_table_add(handle) == RET_FAIL);

  CU_ASSERT(read_bytes_from_file((char *) valid_id[1], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(data, data_len, &handle) == 0);
  free(data);

  CU_ASSERT(server_table_add(handle) == OK);
  pelz_log(LOG_DEBUG, "Server Table Add Successful");

  //Testing the private pkey add
  CU_ASSERT(private_pkey_init() == OK);
  CU_ASSERT(private_pkey_add(handle) == RET_FAIL);

  CU_ASSERT(read_bytes_from_file((char *) valid_id[2], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(data, data_len, &handle) == 0);
  free(data);

  CU_ASSERT(private_pkey_add(handle) == OK);
  CU_ASSERT(private_pkey_free() == OK);
  pelz_log(LOG_DEBUG, "Private Key Add Successful");

  CU_ASSERT(table_destroy(KEY) == OK);
  CU_ASSERT(table_destroy(SERVER) == OK);
  pelz_log(LOG_DEBUG, "Test Table Add Function Finish");
}

void test_table_lookup(void)
{
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
  const char *key_str[6] = { "KIENJCDNHVIJERLMALIDFEKIUFDALJFG", "KALIENGVBIZSAIXKDNRUEHFMDDUHVKAN", "HVIJERLMALIDFKDN",
    "NGVBIZSAIXKDNRUE", "EKIUFDALVBIZSAIXKDNRUEHV", "ALIENGVBCDNHVIJESAIXEKIU"
  };
  const char *tmp_id[2] = { "/test/key.txt", "/test/key1txt" };

  pelz_log(LOG_DEBUG, "Test Table Look-up Function Start");
  //Initial load of keys into the key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    key = new_charbuf(strlen(key_str[i]));
    memcpy(key.chars, key_str[i], key.len);
    CU_ASSERT(key_table_add_key(tmp, key) == OK);
    free_charbuf(&tmp);
    secure_free_charbuf(&key);
  }

  //Initial load of certs into the server table
  CU_ASSERT(read_bytes_from_file((char *) valid_id[6], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(data, data_len, &handle) == 0);
  free(data);
  CU_ASSERT(server_table_add(handle) == OK);

  CU_ASSERT(read_bytes_from_file((char *) valid_id[7], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(data, data_len, &handle) == 0);
  free(data);
  CU_ASSERT(server_table_add(handle) == OK);

  //Testing the look-up function for key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    CU_ASSERT(table_lookup(KEY, tmp, &index) == OK);
    CU_ASSERT(index == i);
    free_charbuf(&tmp);
    index = 0;
  }

  //Testing id not found for key table
  tmp = copy_CWD_to_id(prefix, tmp_id[0]);
  CU_ASSERT(table_lookup(KEY, tmp, &index) == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, tmp_id[1]);
  CU_ASSERT(table_lookup(KEY, tmp, &index) == NO_MATCH);
  free_charbuf(&tmp);

  //Testing the look-up function for server table
  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  CU_ASSERT(table_lookup(SERVER, tmp, &index) == OK);
  CU_ASSERT(index == 0);
  free_charbuf(&tmp);
  index = 0;

  tmp = new_charbuf(strlen("TestServer"));
  memcpy(tmp.chars, "TestServer", tmp.len);
  CU_ASSERT(table_lookup(SERVER, tmp, &index) == OK);
  CU_ASSERT(index == 1);
  free_charbuf(&tmp);
  index = 0;

  //Testing id not found for server table
  tmp = new_charbuf(strlen("TestTestTest"));
  memcpy(tmp.chars, "TestTestTest", tmp.len);
  CU_ASSERT(table_lookup(SERVER, tmp, &index) == NO_MATCH);
  free_charbuf(&tmp);

  CU_ASSERT(table_destroy(KEY) == OK);
  CU_ASSERT(table_destroy(SERVER) == OK);
  pelz_log(LOG_DEBUG, "Test Table Look-up Function Finish");
}

void test_table_delete(void)
{
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
  const char *key_str[6] = { "KIENJCDNHVIJERLMALIDFEKIUFDALJFG", "KALIENGVBIZSAIXKDNRUEHFMDDUHVKAN", "HVIJERLMALIDFKDN",
    "NGVBIZSAIXKDNRUE", "EKIUFDALVBIZSAIXKDNRUEHV", "ALIENGVBCDNHVIJESAIXEKIU"
  };
  const char *tmp_id[2] = {
    "/test/key.txt", "/test/key1txt"
  };
  pelz_log(LOG_DEBUG, "Test  Table Delete Function Start");
  //Initial load of keys into the key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    key = new_charbuf(strlen(key_str[i]));
    memcpy(key.chars, key_str[i], key.len);
    CU_ASSERT(key_table_add_key(tmp, key) == OK);
    free_charbuf(&tmp);
    secure_free_charbuf(&key);
  }

  //Initial load of certs into the server table
  CU_ASSERT(read_bytes_from_file((char *) valid_id[6], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(data, data_len, &handle) == 0);
  free(data);
  CU_ASSERT(server_table_add(handle) == OK);

  CU_ASSERT(read_bytes_from_file((char *) valid_id[7], &data, &data_len) == 0);
  CU_ASSERT(kmyth_sgx_unseal_nkl(data, data_len, &handle) == 0);
  free(data);
  CU_ASSERT(server_table_add(handle) == OK);

  //Testing the delete function for key table
  tmp = copy_CWD_to_id(prefix, valid_id[3]);
  CU_ASSERT(table_delete(KEY, tmp) == OK);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[5]);
  CU_ASSERT(table_delete(KEY, tmp) == OK);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  CU_ASSERT(table_delete(KEY, tmp) == OK);
  free_charbuf(&tmp);

  //Testing that if the delete function does not find key_id then does not delete for valid files and non-valid files
  tmp = copy_CWD_to_id(prefix, tmp_id[0]);
  CU_ASSERT(table_delete(KEY, tmp) == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, tmp_id[1]);
  CU_ASSERT(table_delete(KEY, tmp) == NO_MATCH);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("adaj;ldkjidka;dfkjai"));
  memcpy(tmp.chars, "adaj;ldkjidka;dfkjai", tmp.len);
  CU_ASSERT(table_delete(KEY, tmp) == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[5]);
  CU_ASSERT(table_delete(KEY, tmp) == NO_MATCH);
  free_charbuf(&tmp);

  //Testing the delete function for server table
  tmp = new_charbuf(strlen("TestTestTest"));
  memcpy(tmp.chars, "TestTestTest", tmp.len);
  CU_ASSERT(table_delete(SERVER, tmp) == NO_MATCH);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  CU_ASSERT(table_delete(SERVER, tmp) == OK);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  CU_ASSERT(table_delete(SERVER, tmp) == NO_MATCH);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("TestServer"));
  memcpy(tmp.chars, "TestServer", tmp.len);
  CU_ASSERT(table_delete(SERVER, tmp) == OK);
  free_charbuf(&tmp);

  CU_ASSERT(table_destroy(KEY) == OK);
  CU_ASSERT(table_destroy(SERVER) == OK);
  pelz_log(LOG_DEBUG, "Test Table Delete Function Finish");
}
