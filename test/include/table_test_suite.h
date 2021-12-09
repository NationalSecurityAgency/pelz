/*
 * table_test_suite.h
 */

#ifndef TABLE_TEST_SUITE_H_
#define TABLE_TEST_SUITE_H_

#include <common_table.h>
#include <key_table.h>
#include <CUnit/CUnit.h>

// Adds all tests to table suite in main test runner
int table_suite_add_tests(CU_pSuite suite);

// Tests
void test_table_destroy(void);
void test_table_add(void);
void test_table_lookup(void);
void test_table_delete(void);

/**
 * <pre>
 * This function destroys the table specified by type.
 * <pre>
 *
 * @param[in] type The type of table to be destroyed (ex: key_table or server_table)
 *
 * @return OK on success, an error message indicating the type of
 *                    error otherwise.
 */
TableResponseStatus table_destroy(TableType type);

/**
 * <pre>
 * This function deletes a value in hash table based on location in id.
 * <pre>
 *
 * @param[in] type The table type that the id and value needs to be deleted from
 * @param[in] id.chars Table value identifier
 * @param[in] id.len The length of the identifier
 *
 * @return OK on success, an error message indicating the type of
 *                    error otherwise.
 */
TableResponseStatus table_delete(TableType type, charbuf id);

/**
 * <pre>
 * This function to add values into the server hash table.
 * </pre>
 *
 * @param[in] handle The handle value for the cert data location in the kmyth unseal data table
 * @param[in] server_table The server table that the new cert needs to be added to
 * @param[out] server_table The server table with the new added cert
 *
 * @return OK on success, an error message indicating the type of
 *                    error otherwise.
 */
TableResponseStatus server_table_add(uint64_t handle);

/**
 * <pre>
 * This function initializes a pkey.
 * <pre>
 *
 * @param[in] private_pkey The pointer for pkey to be initialized
 * @param[out] private_pkey The initialized pkey
 *
 * @return OK on success, an error message indicating the type of
 *                    error otherwise.
 */
TableResponseStatus private_pkey_init(void);

/**
 * <pre>
 * This function frees the pkey.
 * <pre>
 *
 * @param[in] private_pkey The pointer for pkey to be freed
 *
 * @return OK on success, an error message indicating the type of
 *                    error otherwise.
 */
TableResponseStatus private_pkey_free(void);

/**
 * <pre>
 * This function adds a pkey from unseal table based on handle.
 * </pre>
 *
 * @param[in] handle The handle value for the pkey data location in the kmyth unseal data table
 * @param[in] private_pkey The empty or old pkey
 * @param[out] private_pkey The new pkey
 *
 * @return OK on success, an error message indicating the type of
 *                    error otherwise.
 */
TableResponseStatus private_pkey_add(uint64_t handle);

#endif /* TABLE_TEST_SUITE_H_ */
