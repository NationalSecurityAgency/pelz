/**
 * @file  aes_keywrap_test.h
 *
 * Provides unit tests for the Pelz AES keywrap (RFC-3394 - no padding)
 * cipher functionality implemented in:
 *     - tpm2/src/cipher/aes_keywrap_3394nopad.c
 *     - tpm2/src/cipher/aes_keywrap_5649pad.c
 */

#ifndef AES_KEYWRAP_TEST_H
#define AES_KEYWRAP_TEST_H

#include <stdint.h>
#include <stdbool.h>
#include <CUnit/CUnit.h>

#include "aes_keywrap_3394nopad.h"

/**
 * Specify maximum number of test vector sets (vector files) that can be
 * contained within a "vector set compilation" (used to size that array).
 */
#define MAX_VECTOR_SETS_IN_COMPILATION 20

/**
 * Specify maximum number of test vectors to process when parsing
 * a test vector file.
 */
#define MAX_KEYWRAP_TEST_VECTOR_COUNT 500
#define MAX_GCM_TEST_VECTOR_COUNT 7875

/**
 * Specify the maximum length (in chars) of a test vector component
 * This is needed to appropriately size the buffers used to parse and
 * process test vector components read from a file. For example, a
 * value of 2176 (2048 + 128) supports up to a 2048 hexadecimal character
 * string that can specify a 1024-byte or 8192-bit test vector component,
 * as well as up to 128 leading/trailing characters.
 */
#define MAX_TEST_VECTOR_COMPONENT_LENGTH 2176

typedef struct cipher_vector_set
{
  char *desc;
  char *func_to_test;
  char *path;
} cipher_vector_set;

typedef struct cipher_vector_compilation
{
  size_t count;
  cipher_vector_set sets[MAX_VECTOR_SETS_IN_COMPILATION];
} cipher_vector_compilation;

/**
 * This function adds all of the tests contained in
 * tpm2/test/cipher/aes_keywrap_test.c to a test suite parameter passed in by
 * the caller. This allows a top-level 'test-runner' application to include
 * them in the set of tests that it runs.
 *
 * @param[in]  suite  CUnit test suite that this function will add all of
 *                    the Pelz AES keywrap cipher functionality tests to.
 *
 * @return     0 on success, 1 on error
 */
int aes_keywrap_add_tests(CU_pSuite suite);

//--------------------- Test Utilities -------------------------------

/**
 * The NIST test vectors are specified as strings representing hexadecimal
 * values. These hex strings, read from the test vector files, must be
 * converted to byte arrays with the corresponding value, in order to
 * comply with kmyth's cipher API. This simple utility provides the
 * hexadecimal string to byte array format conversion required to pass the
 * specified input parameters to Pelz cipher functions and/or compare
 * resultant output parameters to the expected result.
 *
 * @param[out] result  - Byte array corresponding to input hex string value
 *
 * @param[in]  hex_str - hexadecimal string to be converted
 *
 * @param[in]  size    - length (in hex chars) of input string
 *
 * @return     0 on success, 1 on error
 */
int convert_HexString_to_ByteArray(char **result, char *hex_str, int str_size);

/**
 * Parses NIST AES key wrap/unwrap test vector files.
 *
 * NOTE: Designed to parse NIST AES key wrap/unwrap test vectors ONLY
 *       Not guarenteed to work on other files
 *
 * @param[out] suite  CUnit test suite that this function will add all of
 *                    the Pelz AES keywrap cipher functionality tests to.
 *
 * @return     0 on success, 1 on error
 */

/**
 * Return a single AES Key Wrap test vector to be applied to (validate)
 * Pelz's AEC Key Wrap cipher (RFC-3394 and RFC-5649) functionality.
 *
 * IMPORTANT NOTE: Parses only NIST AES KW/KWP test vector files (or
 * other test vector files that adhere strictly to this format.
 *
 * The test vector values in the file are specified by groupings of lines
 * containing:
 *
 *     'K = [string representing hexadecimal byte array value]'
 *     'P = [string representing hexadecimal byte array value]'
 *     'C = [string representing hexadecimal byte array value]'
 *
 * for the encrypt test vectors and
 *
 *     'K = [string representing hexadecimal byte array value]'
 *     'C = [string representing hexadecimal byte array value]'
 *     'P = [string representing hexadecimal byte array value]'
 *
 * for the decrypt test vectors. If the expected result is decryption failure,
 * the last (P = ...) line is replaced by:
 *
 *     'FAIL'
 *
 * In parsing the file, we look for these groupings and, upon finding the
 * first line of one, process that set of lines from the file. Any lines in the
 * file that are not part of one of these test vector groupings are ignored.
 *
 * @param[in]  fid         - pointer to file descriptor for test vector file
 *
 * @param[out] K_vec       - pointer to byte array used to return 'K' (key)
 *                           component of test vector
 *
 * @param[out] K_vec_len   - pointer to length (in bytes) of value being
 *                           returned in 'K_vec' byte array
 *
 * @param[out] P_vec       - pointer to byte array used to return 'P'
 *                           (plaintext) component of test vector
 *
 * @param[out] P_vec_len   - pointer to length (in bytes) of value being
 *                           returned in 'P_vec' byte array
 *
 * @param[out] C_vec       - pointer to byte array used to return 'C'
 *                           (ciphertext) component of test vector
 *
 * @param[out] C_vec_len   - pointer to length (in bytes) of value being
 *                           returned in 'C_vec' byte array
 *
 * @param[out] expect_pass - pointer to boolean indicating whether
 *                           application of the test vector should produce
 *                           a PASS result (i.e., if true, the vector should
 *                           not produce an error, if false, the vector is
 *                           expected to produce an error)
 *
 * @return     0 on success, 1 on error
 */
int get_aes_keywrap_vector_from_file(FILE * fid,
  uint8_t ** K_vec,
  size_t * K_vec_len, uint8_t ** P_vec, size_t * P_vec_len, uint8_t ** C_vec, size_t * C_vec_len, bool * expect_pass);

//--------------------- Tests ------------------------------------------------

/**
 * Test to verify parameter handling/enforcement by the Pelz AES key
 * wrap/unwrap API (e.g., tests behavior when invalid parameters are
 * provided, etc.)
 */
void test_aes_keywrap_parameters(void);

/**
 * Runs set of test vectors for AES key wrap/unwrap through Pelz
 * implementation of this cipher functionality and validates
 * that the results match those specified by the test vectors.
 */
void test_aes_keywrap_vectors(void);

#endif
