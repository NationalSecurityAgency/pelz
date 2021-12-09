// TEST FILE FOR TEST PURPOSES ONLY

#ifndef INCLUDE_PELZ_ENCLAVE_T_H_
#define INCLUDE_PELZ_ENCLAVE_T_H_

#include "pelz_request_handler.h"
#include "common_table.h"
#include "key_table.h"
#include "pelz_io.h"
#include "charbuf.h"
#include "util.h"
#include "stdbool.h"

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif
  TableResponseStatus table_destroy(TableType type);
  TableResponseStatus table_delete(TableType type, charbuf id);
  TableResponseStatus server_table_add(uint64_t handle);
  TableResponseStatus private_pkey_init(void);
  TableResponseStatus private_pkey_free(void);
  TableResponseStatus private_pkey_add(uint64_t handle);
  RequestResponseStatus pelz_request_handler(RequestType request_type, charbuf key_id, charbuf data, charbuf * output);
  int key_load(size_t key_id_len, unsigned char *key_id, size_t * key_len, unsigned char **key);
  void ocall_malloc(size_t size, char **buf);
  void ocall_free(void *ptr, size_t len);
#ifdef __cplusplus
}
#endif                          /* __cplusplus */

#endif
