/*
 * main.c
 *
 * Main function to do unit testing for PELZ.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "aes_keywrap_test.h"
#include "key_table_test_suite.h"
#include "util_test_suite.h"
#include <pelz_log.h>
#include <CharBuf.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

// Blank Suite's init and cleanup code
int init_suite(void)
{
	return (0);
}
int clean_suite(void)
{
	return (0);
}

//Main function for the unit testing of the Pelz Service application
int main(int argc, char **argv)
{
  char cwd[1024];
  char *tmp_id;
  CharBuf id;
  char *key[6] = { "KIENJCDNHVIJERLMALIDFEKIUFDALJFG", "KALIENGVBIZSAIXKDNRUEHFMDDUHVKAN", "HVIJERLMALIDFKDN",
		   "NGVBIZSAIXKDNRUE", "EKIUFDALVBIZSAIXKDNRUEHV", "ALIENGVBCDNHVIJESAIXEKIU"};

  set_app_name("pelz");
  set_app_version("0.0.0");
  set_applog_path("./test/log/pelz.log");
  set_applog_severity_threshold(LOG_INFO);

  getcwd(cwd, sizeof(cwd));
  tmp_id = "/test/key1.txt";
  id = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(id.chars, cwd, strlen(cwd));
  memcpy(&id.chars[strlen(cwd)], tmp_id, (id.len - strlen(cwd)));
  for (int i = 1; i < 7; i++)
  {
    tmp_id = calloc((id.len + 1), sizeof(char));
    memcpy(tmp_id, id.chars, id.len);
    tmp_id[id.len - 5] = i + '0';
    FILE *fp = fopen(tmp_id, "w");
    fprintf(fp, "%s", key[i-1]);
    fclose(fp);
    free(tmp_id);
  }

  pelz_log(LOG_DEBUG, "Start Unit Test");
  // Initialize CUnit test registry
  if (CUE_SUCCESS != CU_initialize_registry())
  {
    return CU_get_error();
  }

  // Create and configure the AES Key Wrap cipher test suite
  CU_pSuite aes_keywrap_test_suite = NULL;

  aes_keywrap_test_suite = CU_add_suite("AES Key Wrap Cipher Test Suite",
                                        init_suite, clean_suite);
  if (NULL == aes_keywrap_test_suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (aes_keywrap_add_tests(aes_keywrap_test_suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add key table suite ---- tests key table init/add/lookup/destroy functions
  CU_pSuite key_table_Suite = NULL;

  key_table_Suite = CU_add_suite("Key Table Suite", init_suite, clean_suite);
  if(NULL == key_table_Suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if(key_table_suite_add_tests(key_table_Suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add utility suite --- tests util/util.h functions
  CU_pSuite utility_Suite = NULL;

  utility_Suite = CU_add_suite("Utility Suite", init_suite, clean_suite);
  if(NULL == utility_Suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if(utility_suite_add_tests(utility_Suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  pelz_log(LOG_DEBUG, "Run tests using basic interface");
  // Run tests using basic interface
  CU_basic_run_tests();
  //CU_console_run_tests();
  //CU_automated_run_tests();

  for (int i = 1; i < 7; i++)
  {
    tmp_id = calloc((id.len + 1), sizeof(char));
    memcpy(tmp_id, id.chars, id.len);
    tmp_id[id.len - 5] = i + '0';
    remove(tmp_id);
    free(tmp_id);
  }

  pelz_log(LOG_DEBUG, "Clean up registry and return");
  // Clean up registry and return
  CU_cleanup_registry();
  return CU_get_error();
}


