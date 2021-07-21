/*
 * test_helper_functions.c
 */

#include "charbuf.h"
#include "key_table.h"
#include <unistd.h>
#include <string.h>

#ifdef PELZ_SGX_UNTRUSTED
#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"
#endif

#ifdef PELZ_SGX_TRUSTED
#include "sgx_trts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_t.h"
#endif

charbuf copy_CWD_to_id(char *prefix, char *postfix)
{
  charbuf newBuf;
  char cwd[100];

  getcwd(cwd, sizeof(cwd));
  newBuf = new_charbuf(strlen(prefix) + strlen(cwd) + strlen(postfix));
  memcpy(newBuf.chars, prefix, strlen(prefix));
  memcpy(&newBuf.chars[strlen(prefix)], cwd, strlen(cwd));
  memcpy(&newBuf.chars[strlen(prefix) + strlen(cwd)], postfix, strlen(postfix));
  return (newBuf);
}

int key_table_add_test(charbuf key_id)
{
  charbuf key;

  if (key_table_add(key_id, &key))
  {
    free_charbuf(&key);
    return 1;
  }
  free_charbuf(&key);
  return 0;
}

int key_table_lookup_test(charbuf key_id)
{
  charbuf key;

  if (key_table_lookup(key_id, &key))
  {
    free_charbuf(&key);
    return 1;
  }
  free_charbuf(&key);
  return 0;
}
