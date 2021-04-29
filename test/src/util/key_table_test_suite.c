/*
 * key_table_test_suite.c

 */

#include "key_table_test_suite.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <CharBuf.h>
#include <pelz_log.h>

// Adds all key table tests to main test runner.
int key_table_suite_add_tests(CU_pSuite suite)
{
  if(NULL == CU_add_test(suite, "Test Key Table Initialization/Destruction", test_table_initDestroy))
		  {
    return (1);
		  }
  if(NULL == CU_add_test(suite, "Test all combinations for adding keys to Key Table", test_table_initAddDestroy))
		  {
    return (1);
		  }
  if(NULL == CU_add_test(suite, "Test all Key Table Lookup combinations", test_table_initLookupAddDestroy))
		  {
    return (1);
		  }
  if(NULL == CU_add_test(suite, "Test Key Table Delete", test_table_initLookupAddDeleteDestroy))
		  {
    return (1);
		  }
    return (0);
}

void test_table_initDestroy(void)
{
  CU_ASSERT(key_table_init() == 0)
  CU_ASSERT(key_table_destroy() == 0)
}

void test_table_initAddDestroy(void)
{
  CharBuf tmp;
  CharBuf key;
  char cwd[1024];
  char *valid_id[3] = {"file:/test/key1.txt", "file:/test/key2.txt", "file:/test/key3.txt"};
  char *tmp_id;


  getcwd(cwd, sizeof(cwd));
  pelz_log(LOG_DEBUG, "Test Key Table Add Function");
  CU_ASSERT(key_table_init() == 0)

  //Test that the keys are added to the key table
  for (int i = 0; i < 3; i++)
  {
    tmp = newCharBuf(strlen(valid_id[i]) + strlen(cwd));
    memcpy(tmp.chars, valid_id[i], 5);
    memcpy(&tmp.chars[5], cwd, strlen(cwd));
    memcpy(&tmp.chars[5 + strlen(cwd)], &valid_id[i][5], (tmp.len - strlen(cwd) - 5));
    CU_ASSERT(key_table_add(tmp, &key) == 0)
    freeCharBuf(&tmp);
    freeCharBuf(&key);
  }

  //Test that keys are added if valid without checking if already in table
  for (int i = 0; i < 3; i++)
  {
    tmp = newCharBuf(strlen(valid_id[i]) + strlen(cwd));
    memcpy(tmp.chars, valid_id[i], 5);
    memcpy(&tmp.chars[5], cwd, strlen(cwd));
    memcpy(&tmp.chars[5 + strlen(cwd)], &valid_id[i][5], (tmp.len - strlen(cwd) - 5));
	CU_ASSERT(key_table_add(tmp, &key) == 0)
	freeCharBuf(&tmp);
	freeCharBuf(&key);
  }

  //Test that non-valid keys are not added
  tmp_id = "file:/test/key7.txt";
  tmp = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(tmp.chars, tmp_id, 5);
  memcpy(&tmp.chars[5], cwd, strlen(cwd));
  memcpy(&tmp.chars[5 + strlen(cwd)], &tmp_id[5], (tmp.len - strlen(cwd) - 5));
  CU_ASSERT(key_table_add(tmp, &key) == 1)
  freeCharBuf(&tmp);
  freeCharBuf(&key);

  CU_ASSERT(key_table_destroy() == 0)
  pelz_log(LOG_DEBUG, "Test Key Table Add Function Complete");
}

void test_table_initLookupAddDestroy(void)
{
  CharBuf key;
  CharBuf tmp;
  char cwd[1024];
  char *valid_id[3] = {"file:/test/key1.txt", "file:/test/key2.txt", "file:/test/key3.txt"};
  char *tmp_id;


  getcwd(cwd, sizeof(cwd));
  pelz_log(LOG_DEBUG, "Test Key Table Lookup Function");
  CU_ASSERT(key_table_init() == 0)

  //Initial check if the keys are added when the lookup does not find them
  for (int i = 0; i < 3; i++)
  {
    tmp = newCharBuf(strlen(valid_id[i]) + strlen(cwd));
    memcpy(tmp.chars, valid_id[i], 5);
    memcpy(&tmp.chars[5], cwd, strlen(cwd));
    memcpy(&tmp.chars[5 + strlen(cwd)], &valid_id[i][5], (tmp.len - strlen(cwd) - 5));
    CU_ASSERT(key_table_add(tmp, &key) == 0)
    secureFreeCharBuf(&key);
    freeCharBuf(&tmp);
  }

  //Check that the keys are found and not added twice
  for (int i = 0; i < 3; i++)
  {
    tmp = newCharBuf(strlen(valid_id[i]) + strlen(cwd));
    memcpy(tmp.chars, valid_id[i], 5);
    memcpy(&tmp.chars[5], cwd, strlen(cwd));
    memcpy(&tmp.chars[5 + strlen(cwd)], &valid_id[i][5], (tmp.len - strlen(cwd) - 5));
    CU_ASSERT(key_table_lookup(tmp, &key) == 0)
    secureFreeCharBuf(&key);
    freeCharBuf(&tmp);
  }

  //Check that non-valid file does not load key
  tmp_id = "file:/test/key7.txt";
  tmp = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(tmp.chars, tmp_id, 5);
  memcpy(&tmp.chars[5], cwd, strlen(cwd));
  memcpy(&tmp.chars[5 + strlen(cwd)], &tmp_id[5], (tmp.len - strlen(cwd) - 5));
  CU_ASSERT(key_table_lookup(tmp, &key) == 1)
  secureFreeCharBuf(&key);
  freeCharBuf(&tmp);

  tmp_id = "file:/test/key1txt";
  tmp = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(tmp.chars, tmp_id, 5);
  memcpy(&tmp.chars[5], cwd, strlen(cwd));
  memcpy(&tmp.chars[5 + strlen(cwd)], &tmp_id[5], (tmp.len - strlen(cwd) - 5));
  CU_ASSERT(key_table_lookup(tmp, &key) == 1)
  secureFreeCharBuf(&key);
  freeCharBuf(&tmp);

  CU_ASSERT(key_table_destroy() == 0)
  pelz_log(LOG_DEBUG, "Test Key Table Lookup Function");
}

void test_table_initLookupAddDeleteDestroy(void)
{
  CharBuf key;
  CharBuf tmp;
  char cwd[1024];
  char *valid_id[6] = { "file:/test/key1.txt", "file:/test/key2.txt", "file:/test/key3.txt",
			"file:/test/key4.txt", "file:/test/key5.txt", "file:/test/key6.txt" };
  char *tmp_id;


  getcwd(cwd, sizeof(cwd));
  pelz_log(LOG_DEBUG, "Test Key Table Lookup Function");
  CU_ASSERT(key_table_init() == 0)

  //Initial load of keys into the key table
  for (int i = 0; i < 6; i++)
  {
	tmp = newCharBuf(strlen(valid_id[i]) + strlen(cwd));
	memcpy(tmp.chars, valid_id[i], 5);
	memcpy(&tmp.chars[5], cwd, strlen(cwd));
	memcpy(&tmp.chars[5 + strlen(cwd)], &valid_id[i][5], (tmp.len - strlen(cwd) - 5));
    CU_ASSERT(key_table_add(tmp, &key) == 0)
	secureFreeCharBuf(&key);
	freeCharBuf(&tmp);
  }

  //Testing the delete function
  tmp = newCharBuf(strlen(valid_id[3]) + strlen(cwd));
  memcpy(tmp.chars, valid_id[3], 5);
  memcpy(&tmp.chars[5], cwd, strlen(cwd));
  memcpy(&tmp.chars[5 + strlen(cwd)], &valid_id[3][5], (tmp.len - strlen(cwd) - 5));
  CU_ASSERT(key_table_delete(tmp) == 0)
  freeCharBuf(&tmp);

  tmp = newCharBuf(strlen(valid_id[5]) + strlen(cwd));
  memcpy(tmp.chars, valid_id[5], 5);
  memcpy(&tmp.chars[5], cwd, strlen(cwd));
  memcpy(&tmp.chars[5 + strlen(cwd)], &valid_id[5][5], (tmp.len - strlen(cwd) - 5));
  CU_ASSERT(key_table_delete(tmp) == 0)
  freeCharBuf(&tmp);

  tmp = newCharBuf(strlen(valid_id[0]) + strlen(cwd));
  memcpy(tmp.chars, valid_id[0], 5);
  memcpy(&tmp.chars[5], cwd, strlen(cwd));
  memcpy(&tmp.chars[5 + strlen(cwd)], &valid_id[0][5], (tmp.len - strlen(cwd) - 5));
  CU_ASSERT(key_table_delete(tmp) == 0)
  freeCharBuf(&tmp);

  //Testing that if the delete function does not find key_id then does not delete for valid files and non-valid files
  tmp_id = "file:/test/key.txt";
  tmp = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(tmp.chars, tmp_id, 5);
  memcpy(&tmp.chars[5], cwd, strlen(cwd));
  memcpy(&tmp.chars[5 + strlen(cwd)], &tmp_id[5], (tmp.len - strlen(cwd) - 5));
  CU_ASSERT(key_table_delete(tmp) == 1)
  freeCharBuf(&tmp);

  tmp_id = "file:/test/key1txt";
  tmp = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(tmp.chars, tmp_id, 5);
  memcpy(&tmp.chars[5], cwd, strlen(cwd));
  memcpy(&tmp.chars[5 + strlen(cwd)], &tmp_id[5], (tmp.len - strlen(cwd) - 5));
  CU_ASSERT(key_table_delete(tmp) == 1)
  freeCharBuf(&tmp);

  tmp = newCharBuf(strlen("adaj;ldkjidka;dfkjai"));
  memcpy(tmp.chars, "adaj;ldkjidka;dfkjai", tmp.len);
  CU_ASSERT(key_table_delete(tmp) == 1)
  freeCharBuf(&tmp);

  CU_ASSERT(key_table_destroy() == 0)
  pelz_log(LOG_DEBUG, "Test Key Table Lookup Function");
}
