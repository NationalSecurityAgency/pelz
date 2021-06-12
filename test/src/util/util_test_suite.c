/*
 * util_test_suite.c
 */

#include "util_test_suite.h"
#include "test_helper_functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

#include <charbuf.h>
#include <pelz_log.h>

// Adds tests to utility suite that get executed by pelz-test-unit
int utility_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Verify File Exists With Access test", test_file_check))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Verify Key Load with differing inputs", test_key_load))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test decode and encode Base64Data", test_decodeEncodeBase64Data))
  {
    return 1;
  }

  return 0;
}

/*
 * Tests accuracy of function file_check
 */
void test_file_check(void)
{
  // create "testfile", with sample data, as test input file path
  FILE *fp = fopen("testfile", "w");

  fprintf(fp, "Testing...");
  fclose(fp);

  // NULL input file path should error
  CU_ASSERT(file_check(NULL) == 1);

  // real file input path without read permission should error
  chmod("testfile", 0333);
  CU_ASSERT(file_check("testfile") == 1);

  // real file input path with read permission should verify successfully
  chmod("testfile", 0444);
  CU_ASSERT(file_check("testfile") == 0);

  // non-existing input file path should error
  remove("testfile");
  CU_ASSERT(file_check("testfile") == 1);
}

/*
 * Tests accuracy of function file_check
 */
void test_key_load(void)
{
  KeyEntry key_values;
  char *key_id_prefix[5] =
    { "file:/", "file:", "ftp://user:password@host:port", "ftp://user@host:port", "ftp://localhost:port/" };
  char *key_id_postfix[5] = { "/test/key.txt", "/test/key.pem", "/test/key1.txt", "/test/key1.txt", "/test/key1.txt" };

  pelz_log(LOG_DEBUG, "Start Key Load Test");
  key_values.key_id = copy_CWD_to_id("file:", "/test/key1.txt");
  CU_ASSERT(key_load(key_values.key_id.len, key_values.key_id.chars, &key_values.key.len, &key_values.key.chars) == 0);
  free_charbuf(&key_values.key_id);
  free_charbuf(&key_values.key);

  key_values.key_id = copy_CWD_to_id("file://localhost", "/test/key1.txt");
  CU_ASSERT(key_load(key_values.key_id.len, key_values.key_id.chars, &key_values.key.len, &key_values.key.chars) == 0);
  free_charbuf(&key_values.key_id);
  free_charbuf(&key_values.key);

  for (int i = 0; i < 5; i++)
  {
    key_values.key_id = copy_CWD_to_id(key_id_prefix[i], key_id_postfix[i]);
    CU_ASSERT(key_load(key_values.key_id.len, key_values.key_id.chars, &key_values.key.len, &key_values.key.chars) == 1);
    free_charbuf(&key_values.key_id);
  }
}

void test_decodeEncodeBase64Data(void)
{
  unsigned char *known_raw_data = (unsigned char *) "Hello World";
  size_t known_raw_data_size = strlen((char *) known_raw_data);
  unsigned char *base64_data = NULL;
  size_t base64_data_size = 0;
  unsigned char *raw_data = NULL;
  size_t raw_data_size = 0;

  // Test that encode fails if you hand it null data or data of length 0.
  CU_ASSERT(encodeBase64Data(NULL, 1, &base64_data, &base64_data_size) == 1);
  CU_ASSERT(encodeBase64Data(known_raw_data, 0, &base64_data, &base64_data_size) == 1);

  // Now do a valid encode so we can do some decode tests.
  CU_ASSERT(encodeBase64Data(known_raw_data, known_raw_data_size, &base64_data, &base64_data_size) == 0);

  // This decode should succeed.
  CU_ASSERT(decodeBase64Data(base64_data, base64_data_size, &raw_data, &raw_data_size) == 0);
  CU_ASSERT(memcmp((char *) known_raw_data, (char *) raw_data, raw_data_size) == 0);
  free(raw_data);
  raw_data_size = 0;

  // These decode tests should fail for lack of input data.
  CU_ASSERT(decodeBase64Data(NULL, 1, &raw_data, &raw_data_size) == 1);
  CU_ASSERT(decodeBase64Data(base64_data, 0, &raw_data, &raw_data_size) == 1);

  // This should fail for data too long.
  CU_ASSERT(decodeBase64Data(base64_data, ((size_t) INT_MAX) + 1, &raw_data, &raw_data_size) == 1);
  free(base64_data);
}
