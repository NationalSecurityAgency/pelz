#include <stdio.h>
#include <stdlib.h>

#include "CharBuf.h"
#include "pelz_log.h"
#include "pelz_request_handler.h"
#include "pelz_request_handler_impl.h"
#include "key_table.h"
#include "aes_keywrap_3394nopad.h"

#ifdef SGX
#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"
#endif

RequestResponseStatus pelz_request_handler(RequestType request_type, CharBuf key_id, CharBuf data_in, CharBuf * output)
{
#ifdef SGX
  RequestResponseStatus status;

  pelz_request_handler_impl(eid, &status, request_type, key_id, data_in, output);
#else
  return pelz_request_handler_impl(request_type, key_id, data_in, output);
#endif
}
