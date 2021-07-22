/*
 * enclave_test_suite.h
 */

#ifndef ENCLAVE_TEST_SUITE_H_
#define ENCLAVE_TEST_SUITE_H_

#include <CUnit/CUnit.h>

// Adds all tests to key table suite in main test runner
int enclave_suite_add_tests(CU_pSuite suite);

// Tests
void test_table_initDestroy(void);
void test_table_initAddDestroy(void);
void test_table_initLookupAddDestroy(void);
void test_table_initLookupAddDeleteDestroy(void);

#endif /* ENCLAVE_TEST_SUITE_H_ */
