/*
 * request_test_suite.h
 */

#ifndef REQUEST_TEST_SUITE_H_
#define REQUEST_TEST_SUITE_H_

#include <CUnit/CUnit.h>

// Adds all tests to request suite in main test runner
int request_suite_add_tests(CU_pSuite suite);

// Tests
void test_invalid_key_id(void);
void test_encrypt_decrypt(void);
void test_missing_key_id(void);
void test_invalid_cipher_name(void);
void test_missing_input_data(void);
#endif /* REQUEST_TEST_SUITE_H_ */
