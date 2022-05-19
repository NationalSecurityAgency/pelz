/*
 * cmd_interface_test_suite.c
 */

#include "cmd_interface_test_suite.h"

#include <string.h>
#include <CUnit/CUnit.h>

#include <pelz_log.h>
#include <cmd_interface.h>

// Adds tests to cmd interface suite that get executed by pelz-test-unit
int cmd_interface_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test the checking of arg value", test_check_arg))
  {
    return 1;
  }

  return 0;
}

void test_check_arg(void)
{
  const char *args[18] = { NULL, "seal", "exit", "keytable", "pki", "remove",
          "list", "load", "cert", "private", "ca",
          "SEAL", "sea", "seal ", "seala",
          "remvoe", "PRIVATE", "Private" };

  CU_ASSERT(check_arg((char *) args[0]) == EMPTY);
  CU_ASSERT(check_arg((char *) args[1]) == SEAL);
  CU_ASSERT(check_arg((char *) args[2]) == EX);
  CU_ASSERT(check_arg((char *) args[3]) == KEYTABLE);
  CU_ASSERT(check_arg((char *) args[4]) == PKI);
  CU_ASSERT(check_arg((char *) args[5]) == REMOVE);
  CU_ASSERT(check_arg((char *) args[6]) == LIST);
  CU_ASSERT(check_arg((char *) args[7]) == LOAD);
  CU_ASSERT(check_arg((char *) args[8]) == CERT);
  CU_ASSERT(check_arg((char *) args[9]) == PRIVATE);
  CU_ASSERT(check_arg((char *) args[10]) == CA);

  for (int i = 11; i < 18; i++)
  {
    CU_ASSERT(check_arg((char *) args[i]) == OTHER);
  }
}
