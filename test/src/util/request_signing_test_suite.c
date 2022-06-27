/*
 * request_signing_test_suite.c
 */

#include "request_signing_test_suite.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/x509.h>
#include <openssl/pem.h>


#include <charbuf.h>
#include <pelz_log.h>


#define TEST_KEY_ID "file:/fake/path/to/key.txt"
#define TEST_DATA "0123456789abcdef"


int request_signing_test_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test Signature Creation and Validation", test_create_validate_signature))
  {
    return (1);
  }
  return (0);
}

/* Read remote certificate (X509) and private key from PEM files. */
void load_test_key_pair(X509 **requestor_cert, EVP_PKEY **requestor_privkey)
{
  BIO *cert_bio = BIO_new_file("test/data/node_pub.pem", "r");
  BIO *key_bio = BIO_new_file("test/data/node_priv.pem", "r");

  *requestor_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
  BIO_free(cert_bio);

  *requestor_privkey = PEM_read_bio_PrivateKey(key_bio, NULL, 0, NULL);
  BIO_free(key_bio);
}

void test_create_validate_signature(void)
{
  int ret;
  X509 *requestor_cert;
  EVP_PKEY *requestor_privkey;
  BIO *pem_bio;
  BUF_MEM *pem_buf;
  RequestType req_type = REQ_ENC;
  charbuf key_id, data, requestor_cert_pem, signature;

  // initialize request data
  key_id = new_charbuf(strlen(TEST_KEY_ID));
  memcpy(key_id.chars, TEST_KEY_ID, key_id.len);

  data = new_charbuf(strlen(TEST_DATA));
  memcpy(key_id.chars, TEST_DATA, key_id.len);

  // load key pair from file
  load_test_key_pair(&requestor_cert, &requestor_privkey);

  // convert x509 to pem string
  pem_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(pem_bio, requestor_cert);
  BIO_get_mem_ptr(pem_bio, &pem_buf);
  requestor_cert_pem = new_charbuf(pem_buf->length);
  memcpy(requestor_cert_pem.chars, pem_buf->data, requestor_cert_pem.len);
  BIO_free(pem_bio);
  pem_buf = NULL;
  pem_bio = NULL;

  // create signature
  signature = create_signature(requestor_privkey, &req_type, &key_id, &data, &requestor_cert_pem);
  CU_ASSERT(signature.len > 0);

  // check signature
  ret = validate_signature(&req_type, &key_id, &data, &signature, &requestor_cert_pem);
  CU_ASSERT(ret == 0);

  X509_free(requestor_cert);
  EVP_PKEY_free(requestor_privkey);
}