#ifndef _ENCLAVE_REQUEST_SIGNING_H_
#define _ENCLAVE_REQUEST_SIGNING_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include "charbuf.h"
#include "pelz_request_handler.h"
#include "pelz_enclave.h"

charbuf serialize_request(RequestType request_type, charbuf key_id, charbuf data, charbuf requestor_cert);

bool validate_signature(RequestType request_type, charbuf key_id, charbuf data, charbuf signature, charbuf cert);
  
  



#ifdef __cplusplus
}
#endif
#endif
