/*
 * test_helper_functions.c
 */

#include <test_enclave_helper_functions.h>
#include <charbuf.h>
#include <key_table.h>

#include <sgx_trts.h>
#include <pelz_enclave_t.h>

int test_key_table_add(charbuf key_id)
{
  charbuf key;

  if (key_table_add(key_id, &key))
  {
    return 1;
  }
  secure_free_charbuf(&key);
  return 0;
}

int test_key_table_lookup(charbuf key_id)
{
  charbuf key;

  if (key_table_lookup(key_id, &key))
  {
    return 1;
  }
  secure_free_charbuf(&key);
  return 0;
}
