/*
 * util_test_suite.h
 */

#ifndef UTIL_TEST_SUITE_H_
#define UTIL_TEST_SUITE_H_

#include <util.h>
#include <pelz_io.h>
#include <CUnit/CUnit.h>

// Adds all tests to utility suite in main test runner
int utility_suite_add_tests(CU_pSuite suite);

//TESTS
void test_key_load(void);
void test_file_check(void);
void test_decodeEncodeBase64Data(void);

#endif /* UTIL_TEST_SUITE_H_ */
