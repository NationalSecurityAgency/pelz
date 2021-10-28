/*
 * util_test_suite.c
 */

#include "util_test_suite.h"
#include "test_helper_functions.h"
#include "pelz_enclave_u.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <CUnit/CUnit.h>

#include <kmyth/formatting_tools.h>

#include <charbuf.h>
#include <pelz_log.h>

// Adds tests to utility suite that get executed by pelz-test-unit
int utility_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Verify File Exists With Access test", test_file_check))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test decode and encode Base64Data", test_decodeEncodeBase64Data))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test new charbuf", test_new_charbuf))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test free charbuf", test_free_charbuf))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test compare charbuf", test_cmp_charbuf))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test secure free charbuf", test_secure_free_charbuf))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test finding character index in charbuf", test_get_index_for_char))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test function for copying charbuf contents", test_copy_chars_from_charbuf))
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
  CU_ASSERT(file_check((char *) "testfile") == 1);

  // real file input path with read permission should verify successfully
  chmod("testfile", 0444);
  CU_ASSERT(file_check((char *) "testfile") == 0);

  // non-existing input file path should error
  remove("testfile");
  CU_ASSERT(file_check((char *) "testfile") == 1);
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

void test_new_charbuf(void)
{
  charbuf buf = new_charbuf(1);

  CU_ASSERT(buf.chars != NULL);
  CU_ASSERT(buf.len == 1);
  free_charbuf(&buf);

  buf = new_charbuf(0);
  CU_ASSERT(buf.chars == NULL);
  CU_ASSERT(buf.len == 0);

  buf = new_charbuf(-5);
  CU_ASSERT(buf.chars == NULL);
  CU_ASSERT(buf.len == 0);
}

void test_free_charbuf(void)
{
  charbuf buf = new_charbuf(10);

  free_charbuf(&buf);
  CU_ASSERT(buf.chars == NULL);
  CU_ASSERT(buf.len == 0);
  buf.len = 8;
  free_charbuf(&buf);
  CU_ASSERT(buf.len == 0);
  //make sure it's safe to free twice
  free_charbuf(&buf);
  CU_ASSERT(buf.chars == NULL);
  CU_ASSERT(buf.len == 0);
}

void test_cmp_charbuf(void)
{
  charbuf buf1 = new_charbuf(0);
  charbuf buf2 = new_charbuf(0);

  //NULL tests
  CU_ASSERT(cmp_charbuf(buf1, buf2) == 0);
  buf1 = new_charbuf(10);
  CU_ASSERT(cmp_charbuf(buf1, buf2) == 1);
  CU_ASSERT(cmp_charbuf(buf2, buf1) == -1);

  //Varying length tests
  buf2 = new_charbuf(5);
  memcpy(buf1.chars, "greenchile", 10);
  memcpy(buf2.chars, "green", 5);
  CU_ASSERT(cmp_charbuf(buf1, buf2) == 1);
  CU_ASSERT(cmp_charbuf(buf2, buf1) == -1);
  memcpy(buf2.chars, "greeo", 5);
  CU_ASSERT(cmp_charbuf(buf1, buf2) == -1);
  CU_ASSERT(cmp_charbuf(buf2, buf1) == 1);
  free_charbuf(&buf2);

  //Same length tests
  buf2 = new_charbuf(10);
  memcpy(buf2.chars, "greenchile", 10);
  CU_ASSERT(cmp_charbuf(buf1, buf2) == 0);
  CU_ASSERT(cmp_charbuf(buf2, buf1) == 0);
  memcpy(buf2.chars, "greenchild", 10);
  CU_ASSERT(cmp_charbuf(buf1, buf2) == 1);
  CU_ASSERT(cmp_charbuf(buf2, buf1) == -1);

  free_charbuf(&buf1);
  free_charbuf(&buf2);
}

void test_secure_free_charbuf(void)
{
  charbuf buf = new_charbuf(10);

  secure_free_charbuf(&buf);
  CU_ASSERT(buf.chars == NULL);
  CU_ASSERT(buf.len == 0);
  buf.len = 8;
  secure_free_charbuf(&buf);
  CU_ASSERT(buf.len == 0);
  //make sure it's safe to free twice
  secure_free_charbuf(&buf);
  CU_ASSERT(buf.chars == NULL);
  CU_ASSERT(buf.len == 0);
}

void test_get_index_for_char(void)
{
  charbuf buf = new_charbuf(0);

  //NULL test
  CU_ASSERT(get_index_for_char(buf, 'a', 0, 0) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'a', 0, 1) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'a', 2, 0) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'a', 1, 1) == SIZE_MAX);

  buf = new_charbuf(8);
  memcpy(buf.chars, "hijklmno", 8);

  //test going left from start
  CU_ASSERT(get_index_for_char(buf, 'a', 0, 1) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'h', 0, 1) == 0);
  CU_ASSERT(get_index_for_char(buf, 'o', 0, 1) == SIZE_MAX);

  //test going left from the middle
  CU_ASSERT(get_index_for_char(buf, 'a', 3, 1) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'h', 3, 1) == 0);
  CU_ASSERT(get_index_for_char(buf, 'k', 3, 1) == 3);
  CU_ASSERT(get_index_for_char(buf, 'o', 3, 1) == SIZE_MAX);

  //test going left from the end
  CU_ASSERT(get_index_for_char(buf, 'a', 7, 1) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'h', 7, 1) == 0);
  CU_ASSERT(get_index_for_char(buf, 'k', 7, 1) == 3);
  CU_ASSERT(get_index_for_char(buf, 'o', 7, 1) == 7);

  //test going right from start
  CU_ASSERT(get_index_for_char(buf, 'a', 0, 0) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'h', 0, 0) == 0);
  CU_ASSERT(get_index_for_char(buf, 'o', 0, 0) == 7);

  //test going right from the middle
  CU_ASSERT(get_index_for_char(buf, 'a', 3, 0) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'h', 3, 0) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'k', 3, 0) == 3);
  CU_ASSERT(get_index_for_char(buf, 'o', 3, 0) == 7);

  //test going right from the end
  CU_ASSERT(get_index_for_char(buf, 'a', 7, 0) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'h', 7, 0) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'k', 7, 0) == SIZE_MAX);
  CU_ASSERT(get_index_for_char(buf, 'o', 7, 0) == 7);

  memcpy(buf.chars, "aaaabbbb", 8);

  //Test repeats
  CU_ASSERT(get_index_for_char(buf, 'a', 0, 0) == 0);
  CU_ASSERT(get_index_for_char(buf, 'a', 3, 0) == 3);
  CU_ASSERT(get_index_for_char(buf, 'b', 0, 0) == 4);
  CU_ASSERT(get_index_for_char(buf, 'b', 7, 1) == 7);
  CU_ASSERT(get_index_for_char(buf, 'b', 4, 1) == 4);
  CU_ASSERT(get_index_for_char(buf, 'a', 7, 1) == 3);

  free_charbuf(&buf);
}

void test_copy_chars_from_charbuf(void)
{
  charbuf orig = new_charbuf(10);

  memcpy(orig.chars, "greenchile", 10);

  //Copy half the charbuf
  charbuf dest = copy_chars_from_charbuf(orig, 5);

  CU_ASSERT(dest.len == 5);
  CU_ASSERT(memcmp(dest.chars, "chile", 5) == 0);
  free_charbuf(&dest);

  //Copy the whole charbuf
  dest = copy_chars_from_charbuf(orig, 0);
  CU_ASSERT(dest.len == 10);
  CU_ASSERT(memcmp(dest.chars, "greenchile", 10) == 0);
  CU_ASSERT(cmp_charbuf(orig, dest) == 0);
  CU_ASSERT(orig.chars != dest.chars);
  free_charbuf(&dest);

  //Copy the last character
  dest = copy_chars_from_charbuf(orig, orig.len - 1);
  CU_ASSERT(dest.chars[0] == 'e');
  CU_ASSERT(dest.len == 1);
  free_charbuf(&dest);

  //Copy outside the bounds where index == orig.len
  dest = copy_chars_from_charbuf(orig, orig.len);
  CU_ASSERT(dest.chars == NULL);
  CU_ASSERT(dest.len == 0);

  //Copy outside the bounds where index > orig.len
  dest = copy_chars_from_charbuf(orig, 11);
  CU_ASSERT(dest.chars == NULL);
  CU_ASSERT(dest.len == 0);
}
