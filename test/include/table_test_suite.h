/*
 * table_test_suite.h
 */

#ifndef TABLE_TEST_SUITE_H_
#define TABLE_TEST_SUITE_H_

#include <common_table.h>
#include <CUnit/CUnit.h>

// Adds all tests to table suite in main test runner
int table_suite_add_tests(CU_pSuite suite);

// Tests
void test_table_destroy(void);
void test_table_add(void);
void test_table_lookup_func(void);
void test_table_delete(void);

#endif /* TABLE_TEST_SUITE_H_ */
