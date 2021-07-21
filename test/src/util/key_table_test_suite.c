/*
 * key_table_test_suite.c
 */

#include "key_table_test_suite.h"
#include "test_helper_functions.h"
#include "test_enclave_helper_functions.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cjson/cJSON.h>

#include <charbuf.h>
#include <pelz_log.h>

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"

// Adds all key table tests to main test runner.
int key_table_suite_add_tests(CU_pSuite suite)
{

  if (NULL == CU_add_test(suite, "Test Key Table Initialization/Destruction", test_table_initDestroy))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test all combinations for adding keys to Key Table", test_table_initAddDestroy))
  {
    return (1);
  }/*
  if (NULL == CU_add_test(suite, "Test all Key Table Lookup combinations", test_table_initLookupAddDestroy))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Key Table Delete", test_table_initLookupAddDeleteDestroy))
  {
    return (1);
  }*/
  return (0);
}

void test_table_initDestroy(void)
{
  int ret;

  key_table_init(eid, &ret);
  CU_ASSERT(ret == 0);
  key_table_destroy(eid, &ret);
  CU_ASSERT(ret == 0);
}

void test_table_initAddDestroy(void)
{
  int ret;
  charbuf tmp;
  char *prefix = "file:";
  char *valid_id[3] = { "/test/key1.txt", "/test/key2.txt", "/test/key3.txt" };
  char *tmp_id;

  pelz_log(LOG_DEBUG, "Test Key Table Add Function");
  key_table_init(eid, &ret);
  CU_ASSERT(ret == 0);

  //Test that the keys are added to the key table
  for (int i = 0; i < 3; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    pelz_log(LOG_INFO, "Key ID: %.*s", (int) tmp.len, tmp.chars);
    key_table_add_test(eid, &ret, tmp);
    CU_ASSERT(ret == 0);
    free_charbuf(&tmp);
  }

  //Test that keys are added if valid without checking if already in table
  for (int i = 0; i < 3; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    key_table_add_test(eid, &ret, tmp);
    CU_ASSERT(ret == 0);
    free_charbuf(&tmp);
  }

  //Test that non-valid keys are not added
  tmp_id = "/test/key7.txt";
  tmp = copy_CWD_to_id(prefix, tmp_id);
  key_table_add_test(eid, &ret, tmp);
  CU_ASSERT(ret == 1);
  free_charbuf(&tmp);

  key_table_destroy(eid, &ret);
  CU_ASSERT(ret == 0);
  pelz_log(LOG_DEBUG, "Test Key Table Add Function Complete");
}

void test_table_initLookupAddDestroy(void)
{
  int ret;
  charbuf key;
  charbuf tmp;
  char *prefix = "file:";
  char *valid_id[3] = { "/test/key1.txt", "/test/key2.txt", "/test/key3.txt" };
  char *tmp_id;

  pelz_log(LOG_DEBUG, "Test Key Table Lookup Function");
  key_table_init(eid, &ret);
  CU_ASSERT(ret == 0);

  //Initial check if the keys are added when the lookup does not find them
  for (int i = 0; i < 3; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    //key_table_add(eid, &ret, tmp, &key);
    CU_ASSERT(ret == 0);
    secure_free_charbuf(&key);
    free_charbuf(&tmp);
  }

  //Check that the keys are found and not added twice
  for (int i = 0; i < 3; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    //key_table_lookup(eid, &ret, tmp, &key);
    CU_ASSERT(ret == 0);
    secure_free_charbuf(&key);
    free_charbuf(&tmp);
  }

  //Check that non-valid file does not load key
  tmp_id = "/test/key7.txt";
  tmp = copy_CWD_to_id(prefix, tmp_id);
  //key_table_lookup(eid, &ret, tmp, &key);
  CU_ASSERT(ret == 1);
  secure_free_charbuf(&key);
  free_charbuf(&tmp);

  tmp_id = "/test/key1txt";
  tmp = copy_CWD_to_id(prefix, tmp_id);
  //key_table_lookup(eid, &ret, tmp, &key);
  CU_ASSERT(ret == 1);
  secure_free_charbuf(&key);
  free_charbuf(&tmp);

  key_table_destroy(eid, &ret);
  CU_ASSERT(ret == 0);
  pelz_log(LOG_DEBUG, "Test Key Table Lookup Function");
}

void test_table_initLookupAddDeleteDestroy(void)
{
  int ret;
  charbuf key;
  charbuf tmp;
  char *prefix = "file:";

  char *valid_id[6] = { "/test/key1.txt", "/test/key2.txt", "/test/key3.txt",
    "/test/key4.txt", "/test/key5.txt", "/test/key6.txt"
  };
  char *tmp_id;

  pelz_log(LOG_DEBUG, "Test Key Table Lookup Function");
  key_table_init(eid, &ret);
  CU_ASSERT(ret == 0);
  //Initial load of keys into the key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    //key_table_add(eid, &ret, tmp, &key);
    CU_ASSERT(ret == 0);
    secure_free_charbuf(&key);
    free_charbuf(&tmp);
  }

  //Testing the delete function
  tmp = copy_CWD_to_id(prefix, valid_id[3]);
  key_table_delete(eid, &ret, tmp);
  CU_ASSERT(ret == 0);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[5]);
  key_table_delete(eid, &ret, tmp);
  CU_ASSERT(ret == 0);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  key_table_delete(eid, &ret, tmp);
  CU_ASSERT(ret == 0);
  free_charbuf(&tmp);

  //Testing that if the delete function does not find key_id then does not delete for valid files and non-valid files
  tmp_id = "/test/key.txt";
  tmp = copy_CWD_to_id(prefix, tmp_id);
  key_table_delete(eid, &ret, tmp);
  CU_ASSERT(ret == 1);
  free_charbuf(&tmp);

  tmp_id = "/test/key1txt";
  tmp = copy_CWD_to_id(prefix, tmp_id);
  key_table_delete(eid, &ret, tmp);
  CU_ASSERT(ret == 1);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("adaj;ldkjidka;dfkjai"));
  memcpy(tmp.chars, "adaj;ldkjidka;dfkjai", tmp.len);
  key_table_delete(eid, &ret, tmp);
  CU_ASSERT(ret == 1);
  free_charbuf(&tmp);

  key_table_destroy(eid, &ret);
  CU_ASSERT(ret == 0);
  pelz_log(LOG_DEBUG, "Test Key Table Lookup Function");
}
