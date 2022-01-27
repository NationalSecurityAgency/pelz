/*
 * main.c
 *
 * Main function to do unit testing for PELZ.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "util_test_suite.h"
#include "aes_keywrap_test.h"
#include "pelz_json_parser_test_suite.h"
#include "test_pelz_uri_helpers.h"
#include "table_test_suite.h"
#include "request_test_suite.h"
#include "pelz_log.h"

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"
sgx_enclave_id_t eid = 0;

#define ENCLAVE_PATH "sgx/pelz_enclave.signed.so"

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
  int status;

  const char *key_file_id[6] =
    { "test/data/key1.txt", "test/data/key2.txt", "test/data/key3.txt", "test/data/key4.txt", "test/data/key5.txt",
    "test/data/key6.txt"
  };
  const char *key[6] = { "KIENJCDNHVIJERLMALIDFEKIUFDALJFG", "KALIENGVBIZSAIXKDNRUEHFMDDUHVKAN", "HVIJERLMALIDFKDN",
    "NGVBIZSAIXKDNRUE", "EKIUFDALVBIZSAIXKDNRUEHV", "ALIENGVBCDNHVIJESAIXEKIU"
  };

  set_app_name("pelz");
  set_app_version("0.0.0");
  set_applog_max_msg_len(1024);
  set_applog_path("./test/log/pelz.log");
  set_applog_severity_threshold(LOG_DEBUG);

  for (int i = 0; i < 6; i++)
  {
    FILE *fp = fopen(key_file_id[i], "w");

    fprintf(fp, "%s", key[i]);
    fclose(fp);
  }

  status = system("./bin/pelz seal test/data/key1.txt -o test/data/key1.txt.nkl");
  if (status != 0)
  {
    pelz_log(LOG_INFO, "Seal key1.txt to .nkl failed");
  }

  pelz_log(LOG_DEBUG, "Start Unit Test");
  // Initialize CUnit test registry
  if (CUE_SUCCESS != CU_initialize_registry())
  {
    return CU_get_error();
  }

  sgx_create_enclave(ENCLAVE_PATH, 0, NULL, NULL, &eid, NULL);
  kmyth_unsealed_data_table_initialize(eid, &status);
  if (status)
  {
    pelz_log(LOG_ERR, "Unseal Table Init Failure");
    sgx_destroy_enclave(eid);
    return (1);
  }

  // Add utility suite --- tests util/util.h functions
  CU_pSuite utility_Suite = NULL;

  utility_Suite = CU_add_suite("Utility Suite", init_suite, clean_suite);
  if (NULL == utility_Suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (utility_suite_add_tests(utility_Suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add AES Key Wrap test suite --- test util/aes_keywrap_3394nopad.c functions
  CU_pSuite aes_keywrap_test_Suite = NULL;

  aes_keywrap_test_Suite = CU_add_suite("AES Key Wrap Test Suite", init_suite, clean_suite);
  if (NULL == aes_keywrap_test_Suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (aes_keywrap_suite_add_tests(aes_keywrap_test_Suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add pelz json parser suite ---- tests pelz json parser encrypt_parse/decrypt_parse/request_decode/message_encode/error_message_encode functions
  CU_pSuite pelz_json_parser_Suite = NULL;

  pelz_json_parser_Suite = CU_add_suite("Pelz JSON Parser Suite", init_suite, clean_suite);
  if (NULL == pelz_json_parser_Suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (pelz_json_parser_suite_add_tests(pelz_json_parser_Suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add pelz uri helpers suite ---- tests pelz uri helpers
  CU_pSuite test_pelz_uri_helpers_suite = NULL;

  test_pelz_uri_helpers_suite = CU_add_suite("Pelz URI parser test suite", init_suite, clean_suite);
  if (NULL == test_pelz_uri_helpers_suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (test_pelz_uri_helpers_suite_add_tests(test_pelz_uri_helpers_suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add table suite ---- tests table destroy/add/lookup/delete functions 
  CU_pSuite table_Suite = NULL;

  table_Suite = CU_add_suite("Table Suite", init_suite, clean_suite);
  if (NULL == table_Suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (table_suite_add_tests(table_Suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add request suite ---- tests pelz_request_handler functions
  CU_pSuite request_Suite = NULL;

  request_Suite = CU_add_suite("Request Suite", init_suite, clean_suite);
  if (NULL == request_Suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (request_suite_add_tests(request_Suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  pelz_log(LOG_DEBUG, "Run tests using basic interface");
  // Run tests using basic interface
  CU_basic_run_tests();
  //CU_console_run_tests();
  //CU_automated_run_tests();

  kmyth_unsealed_data_table_cleanup(eid, &status);
  sgx_destroy_enclave(eid);
  for (int i = 0; i < 6; i++)
  {
    remove(key_file_id[i]);
  }

  pelz_log(LOG_DEBUG, "Clean up registry and return");
  // Clean up registry and return
  CU_cleanup_registry();
  return CU_get_error();
}
