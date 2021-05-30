/*
 * key_table_test_suite.h
 */

#ifndef KEY_TABLE_TEST_SUITE_H_
#define KEY_TABLE_TEST_SUITE_H_

#include "key_table.h"
#include <CUnit/CUnit.h>

// Adds all tests to key table suite in main test runner
int key_table_suite_add_tests(CU_pSuite suite);

// Tests
void test_table_initDestroy(void);
void test_table_initAddDestroy(void);
void test_table_initLookupAddDestroy(void);
void test_table_initLookupAddDeleteDestroy(void);

#endif /* KEY_TABLE_TEST_SUITE_H_ */
