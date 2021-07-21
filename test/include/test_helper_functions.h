/*
 * test_helper_functions.h
 */

#ifndef TEST_HELPER_FUNCTIONS_H_
#define TEST_HELPER_FUNCTIONS_H_

#ifndef PELZ_SGX_TRUSTED
/**
 * <pre>
 * This function creates a new charbuf that contains the contents of two character strings
 * </pre>
 *
 * @param[in] prefix The character string of the key_id without current working directory prefix (schema notation)
 * @param[in] postfix The character string of the key_id without current working directory postfix (file path)
 *
 * @return charbuf copy of key_id with current working directory
 */
charbuf copy_CWD_to_id(char *prefix, char *postfix);
#endif

#ifndef PELZ_SGX_UNTRUSTED
/**
 * <pre>
 * This function is a wrapper for the unit tests so not to effect enclave code and structure.
 * </pre>
 *
 * @param[in] key_id.chars Key identifier assumed to be null terminated
 * @param[in] key_id.len The length of the key identifier
 *
 * @return 0 on success, 1 on error
 */
  int key_table_add_test(charbuf key_id);

/**
 * <pre>
 * This function is a wrapper for the unit tests so not to effect enclave code and structure.
 * </pre>
 *
 * @param[in] key_id.chars Key identifier assumed to be null terminated
 * @param[in] key_id.len The length of the key identifier
 *
 * @return 0 on success, 1 on error
 */
  int key_table_lookup_test(charbuf key_id);
#endif

#endif /* TEST_HELPER_FUNCTIONS_H_ */
