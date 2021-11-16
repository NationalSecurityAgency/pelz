/*
 * enclave_test_suite.h
 */

#ifndef ENCLAVE_TEST_SUITE_H_
#define ENCLAVE_TEST_SUITE_H_

#include <CUnit/CUnit.h>

// Adds all tests to key table suite in main test runner
int enclave_suite_add_tests(CU_pSuite suite);

// Tests
void test_table_destroy(void);
void test_table_request(void);
void test_table_requestDelete(void);
void test_server_table_destroy(void);
#endif /* ENCLAVE_TEST_SUITE_H_ */
