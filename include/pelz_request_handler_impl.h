#ifndef INCLUDE_PELZ_REQUEST_HANDLER_IMPL_H_
#define INCLUDE_PELZ_REQUEST_HANDLER_IMPL_H_

#include "charbuf.h"
#include "pelz_request_handler.h"

#ifdef __cplusplus
extern "C"
{
#endif

  RequestResponseStatus pelz_request_handler_impl(RequestType request_type, charbuf key_id, charbuf data_in, charbuf * output);

#ifdef __cplusplus
}
#endif
#endif
