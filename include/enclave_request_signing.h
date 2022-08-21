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

/**
 * <pre>
 * Serializes request data so the signature can be validated.
 * </pre>
 *
 * @param[in] request_type   The request type
 * @param[in] key_id         The key_id extracted from the request
 * @param[in] cipher_name    The cipher_name extracted from the request
 * @param[in] data           The data extracted from the request
 * @param[in] iv             The iv extracted from the request, may be empty
 * @param[in] tag            The tag extracted from the request, may be empty
 * @param[in] requestor_cert The requestor_cert extracted from the request
 *
 * @return a charbuf containing the serialized data, or an empty charbuf on error.
 */
  charbuf serialize_request(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf data, charbuf iv, charbuf tag, charbuf requestor_cert);

/**
 * <pre>
 * Validates the signature from the request data
 * </pre>
 *
 * @param[in] request_type   The request type
 * @param[in] key_id         The key_id extracted from the request
 * @param[in] cipher_name    The cipher_name extracted from the request
 * @param[in] data           The data extracted from the request
 * @param[in] iv             The iv extracted from the request, may be empty
 * @param[in] tag            The tag extracted from the request, may be empty
 * @param[in] signature      The signature data extracted from the request
 * @param[in] requestor_cert The requestor_cert extracted from the request
 *
 * @return true if valid, false if invalid
 */
  bool validate_signature(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf data, charbuf iv, charbuf tag, charbuf signature, charbuf cert);
  
  



#ifdef __cplusplus
}
#endif
#endif
