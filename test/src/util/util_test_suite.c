/*
 * util_test_suite.c
 */

#include "util_test_suite.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

#include <CharBuf.h>
#include <pelz_log.h>

// Adds tests to utility suite that get executed by pelz-test-unit
int utility_suite_add_tests(CU_pSuite suite)
{
	if(NULL == CU_add_test(suite, "Verify File Exists With Access test", test_file_check))
	{
		return 1;
	}
	if(NULL == CU_add_test(suite, "Verify Key Id is parsed correctly with differing inputs", test_key_id_parse))
	{
		return 1;
	}
	if(NULL == CU_add_test(suite, "Verify Key Load with differing inputs", test_key_load))
	{
		return 1;
	}
	/*
  if(NULL == CU_add_test(suite, "Test decode and encode Base64Data", test_decodeEncodeBase64Data))
  {
   return 1;
 }
	 */
	return 0;
}

/*
 * Tests accuracy of function file_check
 */
void test_file_check(void)
{
  char cwd[1024];
  char *tmp_id;
  CharBuf id;

  getcwd(cwd, sizeof(cwd));
  // NULL path should return 1
  CU_ASSERT(file_check(NULL) == 1);

  // Fake file path should return 1
  tmp_id = "file:/test/fake_file_path";
  id = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(id.chars, cwd, strlen(cwd));
  memcpy(&id.chars[ strlen(cwd)], tmp_id, (id.len - strlen(cwd)));
  tmp_id = calloc((id.len + 1), sizeof(char));
  memcpy(tmp_id, id.chars, id.len);
  CU_ASSERT(file_check(tmp_id) ==1);
  freeCharBuf(&id);
  free(tmp_id);

  // Real file with permission should return 0
  tmp_id = "/test/temp_file.txt";
  id = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(id.chars, cwd, strlen(cwd));
  memcpy(&id.chars[ strlen(cwd)], tmp_id, (id.len - strlen(cwd)));
  tmp_id = calloc((id.len + 1), sizeof(char));
  memcpy(tmp_id, id.chars, id.len);
  CU_ASSERT(file_check(tmp_id) ==0);
  freeCharBuf(&id);
  free(tmp_id);

  // Real file that I don't have permission to read
  // should return 1
  tmp_id = "/test/temp_file2.txt";
  id = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(id.chars, cwd, strlen(cwd));
  memcpy(&id.chars[ strlen(cwd)], tmp_id, (id.len - strlen(cwd)));
  tmp_id = calloc((id.len + 1), sizeof(char));
  memcpy(tmp_id, id.chars, id.len);
  CU_ASSERT(file_check(tmp_id) ==1);
  freeCharBuf(&id);
  free(tmp_id);
}

/*
 * Tests function key_id_parse
 */
void test_key_id_parse(void)
{
  URIValues uri;
  CharBuf id;
  int id_len = 0;
  char cwd[1024];
  char *tmp_id;
  char *valid_id[7] = { "file:/test/testkeys/key1.txt", "file:///test/testkeys/key1.txt", "file://host.example.com/test/testkeys/key1.txt",
			"file://localhost/test/testkeys/key1.txt", "ftp://user:password@host:port/test/testkeys/key1.txt",
			"ftp://user@host:port/test/testkeys/key1.txt", "ftp://localhost:port/test/testkeys/key1.txt"};
  char *invalid_id[16] = { "file:///test/testkeys/key.txt", "file:/test/testkeys/key.txt", "file://host.example.com/test/testkeys/key.txt",
			"file://localhost/test/testkeys/key.txt", "file:/test/testkeys/key.pem", "file:///test/testkeys/key1txt", "file:/test/testkeys/key1txt",
			"file://host.example.com/test/testkeys/key1txt", "file://localhost/test/testkeys/key1txt", "file:/test/testkeys/key1.tt",
			"file:/test/testkeyskey1.txt", "file:/tet/testkeys/key1.txt", "ftp:/localhost:port/test/testkeys/key1.txt",
			"ftp://localhost:portkey1.txt", "ftp://localhostport/test/testkeys/key1.txt", "adkl;jalfkdja;lkdjal" };

  getcwd(cwd, sizeof(cwd));
  pelz_log(LOG_DEBUG, "Start Key ID Parse Test");
  //Testing all valid Key IDs
  for (int i = 0; i < 7; i++)
  {
	  id_len = strlen(valid_id[i]) - 14;
	  id = newCharBuf(strlen(valid_id[i]) + strlen(cwd));
	  memcpy(id.chars, valid_id[i], id_len);
	  memcpy(&id.chars[id_len], cwd, strlen(cwd));
	  memcpy(&id.chars[id_len + strlen(cwd)], &valid_id[i][id_len], 14);
	  //Test valid Key IDs
	  CU_ASSERT(key_id_parse(id, &uri) == 0);
	  freeCharBuf(&id);
	  if (uri.type == 1)
	  {
	  if (uri.f_values.auth.len != 0)
		freeCharBuf(&uri.f_values.auth);
	  freeCharBuf(&uri.f_values.path);
	  freeCharBuf(&uri.f_values.f_name);
	  }
	  else if (uri.type == 2)
	  {
		freeCharBuf(&uri.ftp_values.host);
		freeCharBuf(&uri.ftp_values.port);
		freeCharBuf(&uri.ftp_values.url_path);
	  }

  }
  //Testing invalid Key IDs
  //Test assumes for FTP that the host, port, url_path are correct (code later needs to be able to check these)
  for (int i = 0; i < 16; i++)
  {
	  id = newCharBuf(strlen(invalid_id[i]));
	  memcpy(id.chars, invalid_id[i], id.len);
	  //Test invalid Key IDs
	  CU_ASSERT(key_id_parse(id, &uri) == 1);
	  freeCharBuf(&id);
  }

  // Real file with permission
  FILE* fp = fopen("temp_file.pem", "w");
  fprintf(fp, "Testing...");
  fclose(fp);
  tmp_id = "file:/temp_file.pem";
  id = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(id.chars, tmp_id, 5);
  memcpy(&id.chars[5], cwd, strlen(cwd));
  memcpy(&id.chars[5 + strlen(cwd)], &tmp_id[5], (id.len - strlen(cwd) - 5));
  CU_ASSERT(key_id_parse(id, &uri) == 0);
  freeCharBuf(&id);
  freeCharBuf(&uri.f_values.path);
  freeCharBuf(&uri.f_values.f_name);
  remove("temp_file.pem");

  // Real file with permission
  fp = fopen("temp_file.py", "w");
  fprintf(fp, "Testing...");
  fclose(fp);
  tmp_id = "file:/temp_file.py";
  id = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(id.chars, tmp_id, 5);
  memcpy(&id.chars[5], cwd, strlen(cwd));
  memcpy(&id.chars[5 + strlen(cwd)], &tmp_id[5], (id.len - strlen(cwd) - 5));
  CU_ASSERT(key_id_parse(id, &uri) == 0);
  freeCharBuf(&id);
  freeCharBuf(&uri.f_values.path);
  freeCharBuf(&uri.f_values.f_name);
  remove("temp_file.py");
}

/*
 * Tests accuracy of function file_check
 */
void test_key_load(void)
{
  KeyEntry key_values;

  int ftp_len = 0;
  char cwd[1024];
  char *tmp_id;
  char *key_id[5] = { "file:/test/testkeys/key.txt", "file:/test/testkeys/key.pem", "ftp://user:password@host:port/test/testkeys/key1.txt",
  			"ftp://user@host:port/test/testkeys/key1.txt", "ftp://localhost:port/test/testkeys/key1.txt"};

  getcwd(cwd, sizeof(cwd));
  pelz_log(LOG_DEBUG, "Start Key Load Test");
  tmp_id = "file:/test/key1.txt";
  key_values.key_id = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(key_values.key_id.chars, tmp_id, 5);
  memcpy(&key_values.key_id.chars[5], cwd, strlen(cwd));
  memcpy(&key_values.key_id.chars[5 + strlen(cwd)], &tmp_id[5], (key_values.key_id.len - strlen(cwd) - 5));
  CU_ASSERT(key_load(&key_values) == 0);
  freeCharBuf(&key_values.key_id);
  freeCharBuf(&key_values.key);
  tmp_id = "file://localhost/test/key1.txt";
  key_values.key_id = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(key_values.key_id.chars, tmp_id, 16);
  memcpy(&key_values.key_id.chars[16], cwd, strlen(cwd));
  memcpy(&key_values.key_id.chars[16 + strlen(cwd)], &tmp_id[16], (key_values.key_id.len - strlen(cwd) - 16));
  CU_ASSERT(key_load(&key_values) == 0);
  freeCharBuf(&key_values.key_id);
  freeCharBuf(&key_values.key);

  for (int i = 0; i < 5; i++)
  {
	  key_values.key_id = newCharBuf(strlen(key_id[i]) + strlen(cwd));
	  if (i < 2)
	  {
		  memcpy(key_values.key_id.chars, key_id[i], 5);
		  memcpy(&key_values.key_id.chars[5], cwd, strlen(cwd));
		  memcpy(&key_values.key_id.chars[5 + strlen(cwd)], &key_id[i][5], (key_values.key_id.len - strlen(cwd) - 5));
	  }
	  else
	  {
		  ftp_len = strlen(key_id[i]) - 14;
		  memcpy(key_values.key_id.chars, key_id[i], ftp_len);
 		  memcpy(&key_values.key_id.chars[ftp_len], cwd, strlen(cwd));
  		  memcpy(&key_values.key_id.chars[ftp_len + strlen(cwd)], &key_id[i][ftp_len], 14);
	  }
	  CU_ASSERT(key_load(&key_values) == 1);
	  freeCharBuf(&key_values.key_id);
  }

  // Real file with permission
  FILE* fp = fopen("temp_file.pem", "w");
  fprintf(fp, "Testing...");
  fclose(fp);
  tmp_id = "file:/temp_file.pem";
  key_values.key_id = newCharBuf(strlen(tmp_id) + strlen(cwd));
  memcpy(key_values.key_id.chars, tmp_id, 5);
  memcpy(&key_values.key_id.chars[5], cwd, strlen(cwd));
  memcpy(&key_values.key_id.chars[5 + strlen(cwd)], &tmp_id[5], (key_values.key_id.len - strlen(cwd) - 5));
  CU_ASSERT(key_load(&key_values) == 1);
  freeCharBuf(&key_values.key_id);
  remove("temp_file.pem");
}

void test_decodeEncodeBase64Data(void){
  unsigned char* known_raw_data = (unsigned char*)"Hello World";
  size_t known_raw_data_size = strlen((char*)known_raw_data);
  unsigned char* base64_data = NULL;
  size_t base64_data_size = 0;
  unsigned char* raw_data = NULL;
  size_t raw_data_size = 0;

  // Test that encode fails if you hand it null data or data of length 0.
  CU_ASSERT(encodeBase64Data(NULL, 1, &base64_data, &base64_data_size) == 1);
  CU_ASSERT(encodeBase64Data(known_raw_data, 0, &base64_data, &base64_data_size) == 1);

  // Now do a valid encode so we can do some decode tests.
  CU_ASSERT(encodeBase64Data(known_raw_data, known_raw_data_size,
			     &base64_data, &base64_data_size) == 0);

  // This decode should succeed.
  CU_ASSERT(decodeBase64Data(base64_data, base64_data_size,
			     &raw_data, &raw_data_size) == 0);
  CU_ASSERT(memcmp((char*)known_raw_data, (char*)raw_data, raw_data_size) == 0);
  free(raw_data);
  raw_data_size = 0;

  // These decode tests should fail for lack of input data.
  CU_ASSERT(decodeBase64Data(NULL, 1, &raw_data, &raw_data_size) == 1);
  CU_ASSERT(decodeBase64Data(base64_data, 0, &raw_data, &raw_data_size) == 1);

  // This should fail for data too long.
  CU_ASSERT(decodeBase64Data(base64_data, ((size_t)INT_MAX)+1, &raw_data, &raw_data_size) == 1);

}
