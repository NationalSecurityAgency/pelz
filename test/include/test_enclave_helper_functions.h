/*
 * test_enclave_helper_functions.h
 */

#ifndef TEST_ENCLAVE_HELPER_FUNCTIONS_H_
#define TEST_ENCLAVE_HELPER_FUNCTIONS_H_

#include "charbuf.h"

#ifdef __cplusplus
extern "C"
{
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
  int test_key_table_add(charbuf key_id);

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
  int test_key_table_lookup(charbuf key_id);
#endif

#ifdef __cplusplus
}
#endif
#endif /* TEST_ENCLAVE_HELPER_FUNCTIONS_H_ */
