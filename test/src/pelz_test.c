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
#include "pelz_json_parser_test_suite.h"
#include "pelz_service_test_suite.h"
#include <pelz_log.h>

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
  set_app_name("pelz");
  set_app_version("0.0.0");
  set_applog_max_msg_len(1024);
  set_applog_path("./test/log/pelz.log");
  set_applog_severity_threshold(LOG_INFO);

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

  // Add pelz json parser suite ---- tests pelz json parser encrypt_parse/decrypt_parse/request_decode/message_encode/error_message_encode functions
  CU_pSuite pelz_json_parser_Suite = NULL;

  pelz_json_parser_Suite = CU_add_suite("Pelz JSON Parser Suite", init_suite, clean_suite);
  if(NULL == pelz_json_parser_Suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if(pelz_json_parser_suite_add_tests(pelz_json_parser_Suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add Pelz Service suite ---- tests pelz service function
  CU_pSuite pelz_service_Suite = NULL;

  pelz_service_Suite = CU_add_suite("Pelz Service Suite", init_suite, clean_suite);
  if(NULL == pelz_service_Suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if(pelz_service_suite_add_tests(pelz_service_Suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  pelz_log(LOG_DEBUG, "Run tests using basic interface");
  // Run tests using basic interface
  CU_basic_run_tests();
  //CU_console_run_tests();
  //CU_automated_run_tests();

  pelz_log(LOG_DEBUG, "Clean up registry and return");
  // Clean up registry and return
  CU_cleanup_registry();
  return CU_get_error();
}


