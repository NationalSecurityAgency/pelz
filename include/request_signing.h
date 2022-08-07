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
 * Validate the signature and certificate for a Pelz request.
 * <pre>
 *
 * @param[in] request_type The request type value.
 * @param[in] key_id The request key ID.
 * @param[in] cipher_name The name of the cipher used for the request.
 * @param[in] iv     The IV included in the request, may be empty.
 * @param[in] tag    The tag inclded in the request, may be empty.
 * @param[in] data The request data to be wrapped/unwrapped (base64 encoded).
 * @param[in] request_sig The digital signature for the request content (base64 encoded).
 * @param[in] requestor_cert The requestor's X509 certificate (base64 encoded DER).
 *
 * @return 0 on success, 1 on error
 *
 */
int validate_signature(RequestType * request_type, charbuf * key_id, charbuf* cipher_name, charbuf* iv, charbuf* tag, charbuf * data, charbuf * request_sig, charbuf * requestor_cert);

/**
 * <pre>
 * Generate the signature for a signed Pelz request.
 * This is intended for demonstration/testing purposes only because it runs outside the enclave.
 * <pre>
 *
 * @param[in] sign_pkey The requestor's private key.
 * @param[in] request_type The request type value.
 * @param[in] key_id The request key ID.
 * @param[in] data The request data to be wrapped/unwrapped (base64 encoded).
 * @param[in] requestor_cert The requestor's X509 certificate (base64 encoded DER).
 *
 * @return A charbuf containing the signature, or an empty charbuf on failure.
 *
 */
charbuf create_signature(EVP_PKEY * sign_pkey, RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * requestor_cert);

/**
 * <pre>
 * Serialize the contents of a signed Pelz request.
 * <pre>
 *
 * @param[in] request_type The request type value.
 * @param[in] key_id The request key ID.
 * @param[in] data The request data to be wrapped/unwrapped (base64 encoded).
 * @param[in] requestor_cert The requestor's X509 certificate (base64 encoded DER).
 *
 * @return A charbuf containing the serialization, or an empty charbuf on failure.
 *
 */
charbuf serialize_request_data(RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * requestor_cert);

#endif /* INCLUDE_REQUEST_SIGNING_H_ */
