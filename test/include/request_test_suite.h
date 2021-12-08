/*
 * request_test_suite.h
 */

#ifndef REQUEST_TEST_SUITE_H_
#define REQUEST_TEST_SUITE_H_

#include <CUnit/CUnit.h>

// Adds all tests to request suite in main test runner
int request_suite_add_tests(CU_pSuite suite);

// Tests
void test_request(void);
#endif /* REQUEST_TEST_SUITE_H_ */
