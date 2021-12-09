// TEST FILE FOR TEST PURPOSES ONLY

#ifndef INCLUDE_PELZ_ENCLAVE_U_H_
#define INCLUDE_PELZ_ENCLAVE_U_H_

#include "test_helper_functions.h"

#include "aes_keywrap_3394nopad.h"
#include "util"
#include "pelz_request_handler.h"
#include "common_table.h"
#include "pelz_io.h"
#include "charbuf.h"
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
  TableResponseStatus key_table_add_key(charbuf key_id, charbuf key);
  TableResponseStatus key_table_add_from_handle(charbuf key_id, uint64_t handle);
  TableResponseStatus key_table_add_from_server(charbuf key_id, charbuf server_id, charbuf server_key_id);
  TableResponseStatus server_table_add(uint64_t handle);
  TableResponseStatus private_pkey_init(void);
  TableResponseStatus private_pkey_free(void);
  TableResponseStatus private_pkey_add(uint64_t handle);
  RequestResponseStatus pelz_request_handler(RequestType request_type, charbuf key_id, charbuf data, charbuf * output);
  void ocall_malloc(size_t size, char **buf);
  void ocall_free(void *ptr, size_t len);
#ifdef __cplusplus
}
#endif                          /* __cplusplus */

#endif
