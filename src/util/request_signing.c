/*
 * request_signing.c
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <openssl/x509.h>

#include <pelz_log.h>
#include <request_signing.h>

#include "ecdh_util.h"

/* Concatenate request data for signing and validation. */
charbuf serialize_request_data(RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * requestor_cert)
{
  // Note: It may be possible to have collisions with this serialization because some field lengths are not fixed.

  uint16_t req_type = *request_type;
  size_t concat_len = sizeof(req_type) + key_id->len + requestor_cert->len + data->len;
  size_t place = 0;
  charbuf serial = new_charbuf(concat_len);

  if (serial.chars == NULL)
  {
    return serial;
  }

  req_type = htons(req_type);

  memcpy(serial.chars + place, &req_type, sizeof(req_type));
  place += sizeof(req_type);
  memcpy(serial.chars + place, key_id->chars, key_id->len);
  place += key_id->len;
  memcpy(serial.chars + place, requestor_cert->chars, requestor_cert->len);
  place += requestor_cert->len;
  memcpy(serial.chars + place, data->chars, data->len);
  place += data->len;

  return serial;
}

charbuf create_signature(EVP_PKEY * sign_pkey, RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * requestor_cert)
{
  // Note: This is included for demonstration/testing purposes.
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

X509 * load_cert(charbuf * requestor_cert)
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

/* Check if the request cert is signed by a known CA. */
int check_cert_chain(X509 *requestor_x509) {
  // FIXME: not yet implemented

  // requires ecall to access stored CA certs

  return 0;
}

int validate_signature(RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * request_sig, charbuf * requestor_cert)
{
  // Note: This is vulnerable to signature replay attacks.

  int ret;
  X509 *requestor_x509;
  EVP_PKEY *requestor_pubkey;
  charbuf serial;

  // Extract the public key from requestor_cert
  requestor_x509 = load_cert(requestor_cert);
  if (requestor_x509 == NULL)
  {
    pelz_log(LOG_ERR, "load_cert failed");
    return 1;
  }

  requestor_pubkey = X509_get_pubkey(requestor_x509);
  if (requestor_pubkey == NULL)
  {
    pelz_log(LOG_ERR, "X509_get_pubkey failed");
    X509_free(requestor_x509);
    return 1;
  }

  serial = serialize_request_data(request_type, key_id, data, requestor_cert);
  if (serial.chars == NULL)
  {
    X509_free(requestor_x509);
    EVP_PKEY_free(requestor_pubkey);
    return 1;
  }

  /* Check that the request signature matches the request data. */
  ret = verify_buffer(requestor_pubkey, serial.chars, serial.len, request_sig->chars, request_sig->len);

  free_charbuf(&serial);
  EVP_PKEY_free(requestor_pubkey);

  if (ret)
  {
    X509_free(requestor_x509);
    return 1;
  }

  ret = check_cert_chain(requestor_x509);
  if (ret)
  {
    X509_free(requestor_x509);
    return 1;
  }

  X509_free(requestor_x509);
  requestor_x509 = NULL;

  return 0;
}
