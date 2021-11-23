#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>
#include <uriparser/Uri.h>

#include "charbuf.h"
#include "pelz_log.h"
#include "pelz_uri_helpers.h"

#include "test_pelz_uri_helpers.h"

int test_pelz_uri_helpers_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test scheme extraction", test_scheme_extraction))
  {
    return 1;
  }
  return 0;
}

void test_scheme_extraction(void)
{
  const char *file_uri = "file:/filename";
  const char *file_uri_2 = "file:///filename";
  const char *pelz_uri = "pelz://common_name/0/key_uid/other_data";
  UriUriA uri;

  uriParseSingleUriA(&uri, file_uri, NULL);
  CU_ASSERT(get_uri_scheme(uri) == FILE_URI);
  char *filename = get_filename_from_key_id(uri);

  CU_ASSERT(strncmp((char *) filename, "/filename", strlen("/filename")) == 0);
  free(filename);
  uriFreeUriMembersA(&uri);

  uriParseSingleUriA(&uri, file_uri_2, NULL);
  CU_ASSERT(get_uri_scheme(uri) == FILE_URI);
  filename = get_filename_from_key_id(uri);
  CU_ASSERT(strncmp((char *) filename, "/filename", strlen("/filename")) == 0);
  free(filename);
  uriFreeUriMembersA(&uri);

  uriParseSingleUriA(&uri, pelz_uri, NULL);
  CU_ASSERT(get_uri_scheme(uri) == PELZ_URI);

  charbuf common_name;
  int port = -1;
  charbuf key_id;
  charbuf additional_data;

  get_pelz_uri_parts(uri, &common_name, &port, &key_id, &additional_data);

  CU_ASSERT(common_name.len == strlen("common_name"));
  CU_ASSERT(memcmp(common_name.chars, "common_name", strlen("common_name")) == 0);

  CU_ASSERT(port == 0);

  CU_ASSERT(key_id.len == strlen("key_uid"));
  CU_ASSERT(memcmp(key_id.chars, "key_uid", strlen("key_uid")) == 0);

  CU_ASSERT(additional_data.len == strlen("other_data"));
  CU_ASSERT(memcmp(additional_data.chars, "other_data", strlen("other_data")) == 0);

  free_charbuf(&common_name);
  free_charbuf(&key_id);
  free_charbuf(&additional_data);
  uriFreeUriMembersA(&uri);
  return;
}
