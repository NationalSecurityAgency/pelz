/*
 * table_test_suite.c
 */

#include "table_test_suite.h"
#include "test_helper_functions.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cjson/cJSON.h>
#include <kmyth/kmyth.h>
#include <kmyth/file_io.h>

#include <charbuf.h>
#include <pelz_log.h>
#include <common_table.h>

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "test_enclave_u.h"
#include "sgx_seal_unseal_impl.h"

// Adds all table tests to main test runner.
int table_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test Table Destruction", test_table_destroy))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Table Addition", test_table_add))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Table Look-up", test_table_lookup_func))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Table Deletion", test_table_delete))
  {
    return (1);
  }
  return (0);
}

int get_file_handle(char *path, uint64_t* handle)
{
  uint8_t *data = NULL;
  size_t data_len = 0;

  if (read_bytes_from_file(path, &data, &data_len))
  {
    pelz_log(LOG_ERR, "read_bytes_from_file function failure");
    return 0;
  }
  if(data_len > 0)
    {
      if (kmyth_sgx_unseal_nkl(eid, data, data_len, handle))
	{
	  pelz_log(LOG_ERR, "kmyth_sgx_unseal_nkl function failure");
	  return 0;
	}
      free(data);
    }
  return 1;
}

void test_table_destroy(void)
{
  TableResponseStatus status;

  pelz_log(LOG_DEBUG, "Test Key Table Destroy Function Start");
  table_destroy(eid, &status, KEY);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, SERVER);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, CA_TABLE);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, TEST);
  CU_ASSERT(status == ERR);
  pelz_log(LOG_DEBUG, "Test Key Table Destroy Function Finish");
}

void test_table_add(void)
{
  TableResponseStatus status;
  charbuf tmp;
  charbuf key;
  charbuf server_id;
  charbuf client_id;
  charbuf port;
  charbuf server_key_id;
  uint64_t handle = 0;
  char prefix[6] = "file:";
  char valid_id[5][28] =
    { "/test/data/key1.txt", "test/data/key1.txt.nkl", "fake_key_id", "test/data/proxy_pub.der.nkl",
    "test/data/node_priv.der.nkl"
  };
  char key_str[33] = "KIENJCDNHVIJERLMALIDFEKIUFDALJFG";

  pelz_log(LOG_DEBUG, "Test Table Add Function Start");

  //Testing the key table add
  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  key = new_charbuf(strlen(key_str));
  memcpy(key.chars, key_str, key.len);
  key_table_add_key(eid, &status, tmp, key);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);
  secure_free_charbuf(&key);
  pelz_log(LOG_INFO, "Key Table add Key complete");

  tmp = copy_CWD_to_id(prefix, valid_id[1]);
  key_table_add_from_handle(eid, &status, tmp, handle);
  CU_ASSERT(status == RET_FAIL);

  if(get_file_handle(valid_id[1], &handle)){
    key_table_add_from_handle(eid, &status, tmp, handle);
    CU_ASSERT(status == OK);
    free_charbuf(&tmp);
    pelz_log(LOG_INFO, "Key Table add from Handle complete");

    //Testing the server table add
    add_cert_to_table(eid, &status, SERVER, handle);
    CU_ASSERT(status == RET_FAIL);
  }
  
  if(get_file_handle(valid_id[3], &handle))
  {
    add_cert_to_table(eid, &status, SERVER, handle);
    CU_ASSERT(status == OK);
    pelz_log(LOG_INFO, "Server Table add complete");
  }

  if(get_file_handle(valid_id[3], &handle))
  {
    get_file_handle(valid_id[3], &handle);
    add_cert_to_table(eid, &status, CA_TABLE, handle);
    CU_ASSERT(status == OK);
    pelz_log(LOG_INFO, "CA Table add complete");

    //Testing the private pkey add
    private_pkey_init(eid, &status);
    CU_ASSERT(status == OK);
    private_pkey_add(eid, &status, handle);
    CU_ASSERT(status == ERR_X509);
  }
  
  if(get_file_handle(valid_id[4], &handle))
  {
    private_pkey_add(eid, &status, handle);
    CU_ASSERT(status == OK);
    pelz_log(LOG_INFO, "Private Pkey add success");
  }
    
  server_id = new_charbuf(strlen("localhost"));
  memcpy(server_id.chars, "localhost", server_id.len);
  client_id = new_charbuf(strlen("TestClient"));
  memcpy(client_id.chars, "TestClient", client_id.len);
  port = new_charbuf(strlen("7000"));
  memcpy(port.chars, "7000", port.len);
  tmp = copy_CWD_to_id(prefix, valid_id[2]);
  server_key_id = new_charbuf(strlen(valid_id[2]));
  memcpy(server_key_id.chars, valid_id[2], server_key_id.len);
  key_table_add_from_server(eid, &status, tmp, server_id, client_id, port, server_key_id);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);
  free_charbuf(&server_id);
  free_charbuf(&client_id);
  free_charbuf(&port);
  free_charbuf(&server_key_id);
  pelz_log(LOG_INFO, "Key Table add from Server complete");

  private_pkey_free(eid, &status);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, KEY);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, SERVER);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, CA_TABLE);
  CU_ASSERT(status == OK);
  pelz_log(LOG_DEBUG, "Test Table Add Function Finish");
}

void test_table_lookup_func(void)
{
  TableResponseStatus status;
  charbuf tmp;
  uint64_t handle = 0;
  int index = 0;
  size_t count = 0;
  char prefix[6] = "file:";

  char valid_id[8][28] = {
    "/test/data/key1.txt", "/test/data/key2.txt", "/test/data/key3.txt", "/test/data/key4.txt", "/test/data/key5.txt",
    "/test/data/key6.txt", "test/data/node_pub.der.nkl", "test/data/proxy_pub.der.nkl"
  };
  char key_str[6][33] = { "KIENJCDNHVIJERLMALIDFEKIUFDALJFG", "KALIENGVBIZSAIXKDNRUEHFMDDUHVKAN", "HVIJERLMALIDFKDN",
    "NGVBIZSAIXKDNRUE", "EKIUFDALVBIZSAIXKDNRUEHV", "ALIENGVBCDNHVIJESAIXEKIU"
  };
  char tmp_id[2][19] = { "/test/data/key.txt", "/test/data/key1txt" };

  pelz_log(LOG_DEBUG, "Test Table Look-up Function Start");
  //Initial load of keys into the key table
  for (int i = 0; i < 6; i++)
  {
    charbuf key = new_charbuf(0);
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    key = new_charbuf(strlen(key_str[i]));
    memcpy(key.chars, key_str[i], key.len);
    key_table_add_key(eid, &status, tmp, key);
    CU_ASSERT(status == OK);
    free_charbuf(&tmp);
    secure_free_charbuf(&key);
  }

  //Initial load of certs into the server table
  get_file_handle(valid_id[6],&handle);
  add_cert_to_table(eid, &status, SERVER, handle);
  CU_ASSERT(status == OK);

  get_file_handle(valid_id[7],&handle);
  add_cert_to_table(eid, &status, SERVER, handle);
  CU_ASSERT(status == OK);

  get_file_handle(valid_id[6],&handle);
  add_cert_to_table(eid, &status, CA_TABLE, handle);
  CU_ASSERT(status == OK);

  get_file_handle(valid_id[7],&handle);
  add_cert_to_table(eid, &status, CA_TABLE, handle);
  CU_ASSERT(status == OK);

  //Testing table count funcion
  table_id_count(eid, &status, KEY, &count);
  CU_ASSERT(status == OK);
  CU_ASSERT(count == 6);
  table_id_count(eid, &status, SERVER, &count);
  CU_ASSERT(status == OK);
  CU_ASSERT(count == 2);

  //Testing table id funcion
  for (int j = 0; j < 6; j++)
  {
    charbuf id = new_charbuf(0);
    tmp = copy_CWD_to_id(prefix, valid_id[j]);
    table_id(eid, &status, KEY, j, &id);
    CU_ASSERT(status == OK);
    CU_ASSERT(memcmp(id.chars, tmp.chars, id.len) == 0);
    free_charbuf(&id);
    free_charbuf(&tmp);
  }

  //Testing the look-up function for key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    test_table_lookup(eid, &status, KEY, tmp, &index);
    CU_ASSERT(status == OK);
    CU_ASSERT(index == i);
    free_charbuf(&tmp);
    index = 0;
  }

  //Testing id not found for key table
  tmp = copy_CWD_to_id(prefix, tmp_id[0]);
  test_table_lookup(eid, &status, KEY, tmp, &index);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, tmp_id[1]);
  test_table_lookup(eid, &status, KEY, tmp, &index);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  //Testing the look-up function for server table
  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  test_table_lookup(eid, &status, SERVER, tmp, &index);
  CU_ASSERT(status == OK);
  CU_ASSERT(index == 0);
  test_table_lookup(eid, &status, CA_TABLE, tmp, &index);
  CU_ASSERT(status == OK);
  CU_ASSERT(index == 0);
  free_charbuf(&tmp);
  index = 0;

  tmp = new_charbuf(strlen("localhost"));
  memcpy(tmp.chars, "localhost", tmp.len);
  test_table_lookup(eid, &status, SERVER, tmp, &index);
  CU_ASSERT(status == OK);
  CU_ASSERT(index == 1);
  test_table_lookup(eid, &status, CA_TABLE, tmp, &index);
  CU_ASSERT(status == OK);
  CU_ASSERT(index == 1);
  free_charbuf(&tmp);
  index = 0;

  //Testing id not found for server table
  tmp = new_charbuf(strlen("TestTestTest"));
  memcpy(tmp.chars, "TestTestTest", tmp.len);
  test_table_lookup(eid, &status, SERVER, tmp, &index);
  CU_ASSERT(status == NO_MATCH);
  test_table_lookup(eid, &status, CA_TABLE, tmp, &index);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  table_destroy(eid, &status, KEY);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, SERVER);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, CA_TABLE);
  CU_ASSERT(status == OK);
  pelz_log(LOG_DEBUG, "Test Table Look-up Function Finish");
}

void test_table_delete(void)
{
  TableResponseStatus status;
  charbuf tmp;
  charbuf key;
  uint64_t handle = 0;
  char prefix[6] = "file:";

  char valid_id[8][28] = {
    "/test/data/key1.txt", "/test/data/key2.txt", "/test/data/key3.txt", "/test/data/key4.txt", "/test/data/key5.txt",
    "/test/data/key6.txt", "test/data/node_pub.der.nkl", "test/data/proxy_pub.der.nkl"
  };
  char key_str[6][33] = { "KIENJCDNHVIJERLMALIDFEKIUFDALJFG", "KALIENGVBIZSAIXKDNRUEHFMDDUHVKAN", "HVIJERLMALIDFKDN",
    "NGVBIZSAIXKDNRUE", "EKIUFDALVBIZSAIXKDNRUEHV", "ALIENGVBCDNHVIJESAIXEKIU"
  };
  char tmp_id[2][19] = {
    "/test/data/key.txt", "/test/data/key1txt"
  };
  pelz_log(LOG_DEBUG, "Test  Table Delete Function Start");
  //Initial load of keys into the key table
  for (int i = 0; i < 6; i++)
  {
    tmp = copy_CWD_to_id(prefix, valid_id[i]);
    key = new_charbuf(strlen(key_str[i]));
    memcpy(key.chars, key_str[i], key.len);
    key_table_add_key(eid, &status, tmp, key);
    CU_ASSERT(status == OK);
    free_charbuf(&tmp);
    secure_free_charbuf(&key);
  }

  //Initial load of certs into the server table
  get_file_handle(valid_id[6], &handle);
  add_cert_to_table(eid, &status, SERVER, handle);
  CU_ASSERT(status == OK);

  get_file_handle(valid_id[7], &handle);
  add_cert_to_table(eid, &status, SERVER, handle);
  CU_ASSERT(status == OK);

  get_file_handle(valid_id[6], &handle);
  add_cert_to_table(eid, &status, CA_TABLE, handle);
  CU_ASSERT(status == OK);

  get_file_handle(valid_id[7], &handle);
  add_cert_to_table(eid, &status, CA_TABLE, handle);
  CU_ASSERT(status == OK);

  //Testing the delete function for key table
  tmp = copy_CWD_to_id(prefix, valid_id[3]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[5]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[0]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);

  //Testing that if the delete function does not find key_id then does not delete for valid files and non-valid files
  tmp = copy_CWD_to_id(prefix, tmp_id[0]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, tmp_id[1]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("adaj;ldkjidka;dfkjai"));
  memcpy(tmp.chars, "adaj;ldkjidka;dfkjai", tmp.len);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = copy_CWD_to_id(prefix, valid_id[5]);
  table_delete(eid, &status, KEY, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  //Testing the delete function for server table
  tmp = new_charbuf(strlen("TestTestTest"));
  memcpy(tmp.chars, "TestTestTest", tmp.len);
  table_delete(eid, &status, SERVER, tmp);
  CU_ASSERT(status == NO_MATCH);
  table_delete(eid, &status, CA_TABLE, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  table_delete(eid, &status, SERVER, tmp);
  CU_ASSERT(status == OK);
  table_delete(eid, &status, CA_TABLE, tmp);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("TestClient"));
  memcpy(tmp.chars, "TestClient", tmp.len);
  table_delete(eid, &status, SERVER, tmp);
  CU_ASSERT(status == NO_MATCH);
  table_delete(eid, &status, CA_TABLE, tmp);
  CU_ASSERT(status == NO_MATCH);
  free_charbuf(&tmp);

  tmp = new_charbuf(strlen("localhost"));
  memcpy(tmp.chars, "localhost", tmp.len);
  table_delete(eid, &status, SERVER, tmp);
  CU_ASSERT(status == OK);
  table_delete(eid, &status, CA_TABLE, tmp);
  CU_ASSERT(status == OK);
  free_charbuf(&tmp);

  table_destroy(eid, &status, KEY);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, SERVER);
  CU_ASSERT(status == OK);
  table_destroy(eid, &status, CA_TABLE);
  CU_ASSERT(status == OK);
  pelz_log(LOG_DEBUG, "Test Table Delete Function Finish");
}
