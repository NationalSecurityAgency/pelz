/*
 * test_helper_functions.h
 */

#ifndef TEST_HELPER_FUNCTIONS_H_
#define TEST_HELPER_FUNCTIONS_H_

/**
 * <pre>
 * This function creates a new CharBuf that contains the contents of two character strings
 * </pre>
 *
 * @param[in] prefix The character string of the key_id without current working directory prefix (schema notation)
 * @param[in] postfix The character string of the key_id without current working directory postfix (file path)
 *
 * @return CharBuf copy of key_id with current working directory
 */
CharBuf copyCWDToId(char *prefix, char *postfix);

#endif /* TEST_HELPER_FUNCTIONS_H_ */
