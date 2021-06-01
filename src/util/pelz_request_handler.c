#include <stdio.h>
#include <stdlib.h>

#include "charbuf.h"
#include "pelz_request_handler.h"

#ifdef PELZ_APP
#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"
#else
#include "pelz_request_handler_impl.h"
#endif

#ifdef PELZ_SGX
#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_t.h"
#endif

RequestResponseStatus pelz_request_handler(RequestType request_type, charbuf key_id, charbuf data_in, charbuf * output)
{

  RequestResponseStatus status;
#if defined(PELZ_SGX) || defined(PELZ_APP)
  pelz_request_handler_impl(eid, &status, request_type, key_id, data_in, output);
#else
  status = pelz_request_handler_impl(request_type, key_id, data_in, output);
#endif
  return status;
}
