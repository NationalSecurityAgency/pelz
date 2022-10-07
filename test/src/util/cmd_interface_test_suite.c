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
  char args[17][9] = { "seal", "exit", "keytable", "pki", "remove",
          "list", "load", "cert", "private", "ca",
          "SEAL", "sea", "seal ", "seala",
          "remvoe", "PRIVATE", "Private" };

  CU_ASSERT(check_arg(NULL) == EMPTY);
  CU_ASSERT(check_arg(args[0]) == SEAL);
  CU_ASSERT(check_arg(args[1]) == EX);
  CU_ASSERT(check_arg(args[2]) == KEYTABLE);
  CU_ASSERT(check_arg(args[3]) == PKI);
  CU_ASSERT(check_arg(args[4]) == REMOVE);
  CU_ASSERT(check_arg(args[5]) == LIST);
  CU_ASSERT(check_arg(args[6]) == LOAD);
  CU_ASSERT(check_arg(args[7]) == CERT);
  CU_ASSERT(check_arg(args[8]) == PRIVATE);
  CU_ASSERT(check_arg(args[9]) == CA);

  for (int i = 10; i < 17; i++)
  {
    CU_ASSERT(check_arg(args[i]) == OTHER);
  }
}
