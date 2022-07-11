/*
 * request_signing.h
 */

#ifndef INCLUDE_REQUEST_SIGNING_H_
#define INCLUDE_REQUEST_SIGNING_H_

#include <openssl/evp.h>

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

/**
 * <pre>
 * Generate the signature for a signed pelz request.
 * This is intended for demonstration/testing purposes only because it runs outside the enclave.
 * <pre>
 *
 * @param[in] sign_pkey The requestor's private key.
 * @param[in] request_type The request type value.
 * @param[in] key_id The request key ID.
 * @param[in] key_id The request data to be wrapped/unwrapped.
 * @param[in] requestor_cert The requestor's X509 certificate.
 *
 * @return A charbuf containing the signature, or an empty charbuf on failure.
 *
 */
charbuf create_signature(EVP_PKEY * sign_pkey, RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * requestor_cert);

charbuf serialize_request_data(RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * requestor_cert);

#endif /* INCLUDE_REQUEST_SIGNING_H_ */
