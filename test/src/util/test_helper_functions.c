/*
 * test_helper_functions.c
 */

#include "test_helper_functions.h"

#include <charbuf.h>
#include <pelz_log.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>

charbuf copy_CWD_to_id(const char *prefix, const char *postfix)
{
  charbuf newBuf;
  char *pointer;
  char cwd[100];

  pointer = getcwd(cwd, sizeof(cwd));
  if (pointer == NULL)
  {
    pelz_log(LOG_ERR, "Get Current Working Directory Failure");
    return (newBuf);
  }
  newBuf = new_charbuf(strlen(prefix) + strlen(cwd) + strlen(postfix));
  memcpy(newBuf.chars, prefix, strlen(prefix));
  memcpy(&newBuf.chars[strlen(prefix)], cwd, strlen(cwd));
  memcpy(&newBuf.chars[strlen(prefix) + strlen(cwd)], postfix, strlen(postfix));
  return (newBuf);
}

int kmyth_sgx_unseal_nkl(uint8_t * input, size_t input_len, uint64_t * handle)
{
  return 0;
}

size_t retrieve_from_unseal_table(uint64_t handle, uint8_t ** buf)
{
  return 0;
}

int enclave_retrieve_key(EVP_PKEY * enclave_sign_privkey, X509 * peer_cert)
{
  return 0;
}
