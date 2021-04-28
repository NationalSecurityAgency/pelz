/*
 * main.c
 *
 * Main function to do unit testing for PELZ.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "aes_key_wrap_test_suite.h"
#include <pelz_log.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <CUnit/Console.h>
#include <CUnit/Automated.h>

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
  set_applog_path("./test/log/pelz.log");
  set_applog_severity_threshold(LOG_INFO);

  pelz_log(LOG_DEBUG, "Start Unit Test");
  //Initialize CUnit test registry
  if(CUE_SUCCESS != CU_initialize_registry())
	    return CU_get_error();

  pelz_log(LOG_DEBUG, "Add AES key wrap suite");
  // Add AES key wrap suite ---- tests aes_key_wrap/unwrap functions
  CU_pSuite AES_key_wrap_Suite = NULL;
  AES_key_wrap_Suite = CU_add_suite("AES Key Wrap Suite", init_suite, clean_suite);
  if(NULL == AES_key_wrap_Suite){
    CU_cleanup_registry();
    return CU_get_error();
  }

  pelz_log(LOG_DEBUG, "Add tests to AES key wrap suite");
  // Add tests to AES key wrap suite
  if(AES_key_wrap_suite_add_tests(AES_key_wrap_Suite)){
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


