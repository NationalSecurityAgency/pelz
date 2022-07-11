/*
 * request_signing.c
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <openssl/x509.h>

#include <kmyth/formatting_tools.h>

#include <pelz_log.h>
#include <request_signing.h>

#include "ecdh_util.h"
#include "common_table.h"
#include "pelz_enclave.h"
#include ENCLAVE_HEADER_UNTRUSTED

/* Concatenate request data for signing and validation. */
charbuf serialize_request_data(RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * requestor_cert)
{
  // Format:
  // request_type (16B, network byte order)
  // key_id (string, null terminated)
  // data (string, null terminated)
  // requestor_cert (string, null terminated)

  // Note: The null terminators are included to mitigate signature collision attacks.

  uint16_t req_type = *request_type;
  size_t concat_len = sizeof(req_type) + key_id->len + requestor_cert->len + data->len + 3;
  charbuf serial = new_charbuf(concat_len);
  unsigned char * dst = serial.chars;

  if (serial.chars == NULL)
  {
    return serial;
  }

  req_type = htons(req_type);
  memcpy(dst, &req_type, sizeof(req_type));

  memcpy(dst, key_id->chars, key_id->len);
  dst += key_id->len;
  *dst++ = '\0';

  memcpy(dst, data->chars, data->len);
  *dst++ = '\0';

  memcpy(dst, requestor_cert->chars, requestor_cert->len);
  dst += requestor_cert->len;
  *dst++ = '\0';

  return serial;
}

charbuf create_signature(EVP_PKEY * sign_pkey, RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * requestor_cert)
{
  // Note: This is included for testing/demonstration/reference.
  // A production implementation should run within the enclave for data protection.

  int ret;
  charbuf signature = new_charbuf(0);
  unsigned char *sig_buff = NULL;
  unsigned int sig_len = 0;
  charbuf serial = serialize_request_data(request_type, key_id, data, requestor_cert);

  if (serial.chars == NULL)
  {
    return signature;
  }

  ret = sign_buffer(sign_pkey, serial.chars, serial.len, &sig_buff, &sig_len);

  free_charbuf(&serial);

  if (ret != EXIT_SUCCESS)
  {
    pelz_log(LOG_ERR, "sign_buffer failed");
    return signature;
  }

  signature = new_charbuf(sig_len);
  memcpy(signature.chars, sig_buff, sig_len);

  return signature;
}

X509 * load_pem_cert(charbuf * requestor_cert)
{
  // create BIO wrapper for cert string
  BIO *cert_bio = BIO_new_mem_buf(requestor_cert->chars, requestor_cert->len);
  if (cert_bio == NULL)
  {
    pelz_log(LOG_ERR, "BIO creation failed");
    return NULL;
  }

  // load requestor's X509 certificate from BIO
  X509 *cert_x509 = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);

  BIO_free(cert_bio);
  cert_bio = NULL;

  if (cert_x509 == NULL)
  {
    pelz_log(LOG_ERR, "Requestor cert could not be read as PEM X509 format.");
    return NULL;
  }

  return cert_x509;
}

int validate_signature(RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * encoded_sig, charbuf * encoded_cert)
{
  // Note: This is vulnerable to signature replay attacks,
  //       but we will use message encryption to avoid leaking sensitive data.

  int ret;
  charbuf decoded_sig = new_charbuf(0);
  charbuf decoded_cert = new_charbuf(0);
  X509 *requestor_x509;
  EVP_PKEY *requestor_pubkey;
  charbuf serial;

  // Undo base64 encoding
  ret = decodeBase64Data(encoded_cert->chars, encoded_cert->len, &decoded_cert.chars, &decoded_cert.len);
  if (ret != 0)
  {
    pelz_log(LOG_ERR, "decodeBase64Data failed");
    free_charbuf(&decoded_sig);
    return 1;
  }

  requestor_x509 = d2i_X509(NULL, (const unsigned char **) &decoded_cert.chars, decoded_cert.len);
  if (requestor_x509 == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "DER to X509 format conversion failed");
    free_charbuf(&decoded_cert);
    return 1;
  }

  // Extract the public key from requestor_cert
  requestor_pubkey = X509_get_pubkey(requestor_x509);
  if (requestor_pubkey == NULL)
  {
    pelz_log(LOG_ERR, "X509_get_pubkey failed");
    free_charbuf(&decoded_cert);
    X509_free(requestor_x509);
    return 1;
  }

  serial = serialize_request_data(request_type, key_id, data, encoded_cert);
  if (serial.chars == NULL)
  {
    free_charbuf(&decoded_cert);
    X509_free(requestor_x509);
    EVP_PKEY_free(requestor_pubkey);
    return 1;
  }

  // Undo base64 encoding
  ret = decodeBase64Data(encoded_sig->chars, encoded_sig->len, &decoded_sig.chars, &decoded_sig.len);
  if (ret != 0)
  {
    pelz_log(LOG_ERR, "decodeBase64Data failed");
    free_charbuf(&decoded_cert);
    X509_free(requestor_x509);
    EVP_PKEY_free(requestor_pubkey);
    return 1;
  }

  /* Check that the request signature matches the request data. */
  ret = verify_buffer(requestor_pubkey, serial.chars, serial.len, decoded_sig.chars, decoded_sig.len);

  free_charbuf(&serial);
  free_charbuf(&decoded_sig);
  EVP_PKEY_free(requestor_pubkey);

  if (ret)
  {
    free_charbuf(&decoded_cert);
    X509_free(requestor_x509);
    return 1;
  }

  /* Check if the request cert is signed by a known CA. */
  TableResponseStatus status;
  verify_cert(eid, &status, decoded_cert);

  free_charbuf(&decoded_cert);
  X509_free(requestor_x509);

  if (status != OK)
  {
    return 1;
  }

  return 0;
}
