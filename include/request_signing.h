/*
 * request_signing.h
 */

#ifndef INCLUDE_REQUEST_SIGNING_H_
#define INCLUDE_REQUEST_SIGNING_H_

#include <charbuf.h>
#include <pelz_request_handler.h>

/**
 * <pre>
 * Validation function. The validation process will determine if the supplied signature and certificate match
 * <pre>
 *
 * @param[in] json Parsed json string in cJSON format to be copied into request values
 *
 * @param[out] data.chars The data to be encrypted
 * @param[out] request_sig.chars The supplied signature
 * @param[out] requestor_cert.len The supplied user certificate
 *
 * @return 0 on success, 1 on error
 *
 */
int validate_signature(RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * request_sig, charbuf * requestor_cert);

#endif /* INCLUDE_REQUEST_SIGNING_H_ */
