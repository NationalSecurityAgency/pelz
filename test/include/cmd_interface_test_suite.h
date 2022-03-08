/*
 * cmd_interface_test_suite.h
 */

#ifndef CMD_INTERFACE_TEST_SUITE_H_
#define CMD_INTERFACE_TEST_SUITE_H_

#include <cmd_interface.h>
#include <CUnit/CUnit.h>

// Adds all tests to cmd interface suite in main test runner
int cmd_interface_suite_add_tests(CU_pSuite suite);

//TESTS
void test_check_arg(void);

#endif /* CMD_INTERFACE_TEST_SUITE_H_ */
