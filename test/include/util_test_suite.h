/*
 * util_test_suite.h
 */

#ifndef UTIL_TEST_SUITE_H_
#define UTIL_TEST_SUITE_H_

#include <key_load.h>
#include <CUnit/CUnit.h>

// Adds all tests to utility suite in main test runner
int utility_suite_add_tests(CU_pSuite suite);

//TESTS
void test_file_check(void);
void test_decodeEncodeBase64Data(void);
void test_new_charbuf(void);
void test_free_charbuf(void);
void test_cmp_charbuf(void);
void test_secure_free_charbuf(void);
void test_get_index_for_char(void);
void test_copy_chars_from_charbuf(void);

#endif /* UTIL_TEST_SUITE_H_ */
