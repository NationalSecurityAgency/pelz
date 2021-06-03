#ifndef INCLUDE_PELZ_REQUEST_HANDLER_IMPL_H_
#define INCLUDE_PELZ_REQUEST_HANDLER_IMPL_H_

#include "charbuf.h"
#include "pelz_request_handler.h"

#ifdef __cplusplus
extern "C"
{
#endif
/**
 * <pre>
 * This function implements the request handling code. It is wrapped by
 * pelz_request_handler to make buidling either the non-SGX version or the SGX
 * version easy.
 * <pre>
 *
 * @param[in] request_type the type of the request (encrypt or decrypt)
 * @param[in] key_id       the key_id of the key to be used for the request
 * @param[in] data_in      the input data
 * @param[out] output      a pointer to a charbuf to hold the output, will
 *                         be created inside the call
 *
 * @return REQUEST_OK on success, an error message indicating the type of
 *                    error otherwise.
 */
  RequestResponseStatus pelz_request_handler_impl(RequestType request_type, charbuf key_id, charbuf data_in, charbuf * output);

#ifdef __cplusplus
}
#endif
#endif
