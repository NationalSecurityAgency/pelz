/*
 * enclave_helper_functions.c
 */

#include "common_table.h"
#include "charbuf.h"

#include "sgx_trts.h"
#include "test_enclave_t.h"

TableResponseStatus test_table_lookup(TableType type, charbuf id, int *index)
{
  return (table_lookup(type, id, index));
}

int test_aes_keywrap_3394nopad_encrypt(size_t key_len, unsigned char *key, size_t inData_len, unsigned char *inData,
  size_t * outData_len, unsigned char **outData)
{
  int ret = -1;
  unsigned char *output = NULL;
  size_t output_len = 0;

  ret = pelz_aes_keywrap_3394nopad_encrypt(key, key_len, inData, inData_len, NULL, NULL, &output, &output_len, NULL, NULL);
  *outData_len = output_len;
  if (output_len != 0)
  {
    ocall_malloc(*outData_len, outData);
    memcpy(*outData, output, *outData_len);
  }
  return (ret);
}

int test_aes_keywrap_3394nopad_decrypt(size_t key_len, unsigned char *key, size_t inData_len, unsigned char *inData,
  size_t * outData_len, unsigned char **outData)
{
  int ret = -1;
  unsigned char *output = NULL;
  size_t output_len = 0;

  ret = pelz_aes_keywrap_3394nopad_decrypt(key, key_len, NULL, 0, inData, inData_len, NULL, 0, &output, &output_len);
  *outData_len = output_len;
  if (output_len != 0)
  {
    ocall_malloc(*outData_len, outData);
    memcpy(*outData, output, *outData_len);
  }
  return (ret);
}
