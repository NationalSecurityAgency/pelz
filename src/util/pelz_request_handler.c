#include <stdio.h>
#include <stdlib.h>

#include "CharBuf.h"
#include "pelz_request_handler.h"

#ifdef APP
#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"
#else
#include "pelz_request_handler_impl.h"
#endif

#ifdef SGX
#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_t.h"
#endif

RequestResponseStatus pelz_request_handler(RequestType request_type, CharBuf key_id, CharBuf data_in, CharBuf * output)
{

  RequestResponseStatus status;
#if defined(SGX) || defined(APP)
  pelz_request_handler_impl(eid, &status, request_type, key_id, data_in, output);
#else
  status = pelz_request_handler_impl(request_type, key_id, data_in, output);
#endif
  return status;
}
