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

#include <kmyth/formatting_tools.h>

#include "common_table.h"
#include "ec_key_cert_marshal.h"
#include "pelz_loaders.h"

#include "sgx_urts.h"
#include "sgx_seal_unseal_impl.h"
#include "pelz_enclave.h"
#include ENCLAVE_HEADER_UNTRUSTED

#define TEST_KEY_ID "file:/fake/path/to/key.txt"
#define TEST_DATA "0123456789abcdef"


int request_signing_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test Signature Creation and Validation (Simplified)", test_create_validate_signature_simple))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Signature Creation and Validation", test_create_validate_signature))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Cert Chain Validation", test_verify_cert_chain))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Cert Chain Validation in Enclave", test_verify_cert_chain_enclave))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Validation of Unsigned Cert", test_invalid_cert_chain_enclave))
  {
    return (1);
  }
  return (0);
}

/* Read remote certificate (X509) and private key from PEM files. */
void load_test_key_pair(X509 **requestor_cert, EVP_PKEY **requestor_privkey)
{
  BIO *cert_bio = BIO_new_file("test/data/worker_pub.pem", "r");
  BIO *key_bio = BIO_new_file("test/data/worker_priv.pem", "r");

  *requestor_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
  BIO_free(cert_bio);

  *requestor_privkey = PEM_read_bio_PrivateKey(key_bio, NULL, 0, NULL);
  BIO_free(key_bio);
}

void test_create_validate_signature_simple(void)
{
  int ret;
  X509 *requestor_cert;
  EVP_PKEY *requestor_privkey;
  EVP_PKEY *requestor_pubkey;
  RequestType req_type = REQ_ENC;
  charbuf key_id, data, requestor_cert_encoded, signature, serial;
  unsigned char *der_buf = NULL;
  int der_len = -1;

  // initialize request data
  key_id = new_charbuf(strlen(TEST_KEY_ID));
  memcpy(key_id.chars, TEST_KEY_ID, key_id.len);

  data = new_charbuf(strlen(TEST_DATA));
  memcpy(key_id.chars, TEST_DATA, key_id.len);

  // load key pair from file
  load_test_key_pair(&requestor_cert, &requestor_privkey);

  // convert x509 to der format
  marshal_ec_x509_to_der(&requestor_cert, &der_buf, &der_len);

  // encode certificate
  ret = encodeBase64Data(der_buf, der_len,
                         &requestor_cert_encoded.chars, &requestor_cert_encoded.len);
  CU_ASSERT(ret == 0);

  // create signature
  signature = create_signature(requestor_privkey, &req_type, &key_id, &data, &requestor_cert_encoded);
  CU_ASSERT(signature.len > 0);

  // Extract the public key from requestor_cert
  requestor_pubkey = X509_get_pubkey(requestor_cert);

  // Check the signature
  serial = serialize_request_data(&req_type, &key_id, &data, &requestor_cert_encoded);
  ret = verify_buffer(requestor_pubkey, serial.chars, serial.len, signature.chars, signature.len);
  CU_ASSERT(ret == 0);

  free(der_buf);
  free_charbuf(&key_id);
  free_charbuf(&data);
  free_charbuf(&requestor_cert_encoded);
  free_charbuf(&signature);

  X509_free(requestor_cert);
  EVP_PKEY_free(requestor_privkey);
}

void test_create_validate_signature(void)
{
  int ret;
  X509 *requestor_cert;
  EVP_PKEY *requestor_privkey;
  uint64_t handle;
  TableResponseStatus status;
  RequestType req_type = REQ_ENC;
  charbuf key_id, data, requestor_cert_encoded, signature, signature_encoded;
  unsigned char *der_buf = NULL;
  int der_len = -1;

  // initialize request data
  key_id = new_charbuf(strlen(TEST_KEY_ID));
  memcpy(key_id.chars, TEST_KEY_ID, key_id.len);

  data = new_charbuf(strlen(TEST_DATA));
  memcpy(key_id.chars, TEST_DATA, key_id.len);

  // load key pair from file
  load_test_key_pair(&requestor_cert, &requestor_privkey);

  // load CA key to enclave
  table_destroy(eid, &status, CA_TABLE);
  CU_ASSERT(status == OK);
  ret = pelz_load_file_to_enclave((char *) "test/data/ca_pub.der.nkl", &handle);
  CU_ASSERT(ret == 0);
  add_cert_to_table(eid, &status, CA_TABLE, handle);
  CU_ASSERT(status == OK);

  // convert x509 to der format
  marshal_ec_x509_to_der(&requestor_cert, &der_buf, &der_len);

  // encode certificate
  ret = encodeBase64Data(der_buf, der_len,
                         &requestor_cert_encoded.chars, &requestor_cert_encoded.len);
  CU_ASSERT(ret == 0);

  // create signature
  signature = create_signature(requestor_privkey, &req_type, &key_id, &data, &requestor_cert_encoded);
  CU_ASSERT(signature.len > 0);

  // encode sigature
  ret = encodeBase64Data(signature.chars, signature.len,
                         &signature_encoded.chars, &signature_encoded.len);
  CU_ASSERT(ret == 0);

  // check signature
  ret = validate_signature(&req_type, &key_id, &data, &signature_encoded, &requestor_cert_encoded);
  CU_ASSERT(ret == 0);

  free(der_buf);
  free_charbuf(&key_id);
  free_charbuf(&data);
  free_charbuf(&requestor_cert_encoded);
  free_charbuf(&signature);

  X509_free(requestor_cert);
  EVP_PKEY_free(requestor_privkey);
}

void test_verify_cert_chain(void)
{
  X509 *requestor_cert;
  X509 *ca_cert;
  EVP_PKEY *requestor_privkey;

  // load client key pair from file
  load_test_key_pair(&requestor_cert, &requestor_privkey);

  // load CA cert from file
  BIO *cert_bio = BIO_new_file("test/data/ca_pub.pem", "r");
  ca_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
  BIO_free(cert_bio);

  // Create cert store
  X509_STORE *store = X509_STORE_new();

  // Put ca certs in the store
  X509_STORE_add_cert(store, ca_cert);

  // Create store context
  X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();

  X509_STORE_CTX_init(store_ctx, store, requestor_cert, NULL);

  int success = X509_verify_cert(store_ctx);

  X509_STORE_CTX_free(store_ctx);
  X509_STORE_free(store);

  X509_free(ca_cert);
  X509_free(requestor_cert);
  EVP_PKEY_free(requestor_privkey);

  CU_ASSERT(success == 1);
}

void test_verify_cert_chain_enclave(void)
{
  int ret;
  TableResponseStatus status;
  X509 *requestor_cert;
  EVP_PKEY *requestor_privkey;
  uint64_t handle;
  unsigned char *der_buf = NULL;
  int der_len = -1;
  charbuf der_cert = new_charbuf(0);

  // initialize CA table
  table_destroy(eid, &status, CA_TABLE);
  CU_ASSERT(status == OK);

  // load key pair from file
  load_test_key_pair(&requestor_cert, &requestor_privkey);

  // convert x509 to der format
  marshal_ec_x509_to_der(&requestor_cert, &der_buf, &der_len);
  der_cert.chars = der_buf;
  der_cert.len = der_len;

  // Check cert chain before loading CA cert
  verify_cert(eid, &status, der_cert);
  CU_ASSERT(status != OK);

  // load CA key to enclave
  ret = pelz_load_file_to_enclave((char *) "test/data/ca_pub.der.nkl", &handle);
  CU_ASSERT(ret == 0);
  add_cert_to_table(eid, &status, CA_TABLE, handle);
  CU_ASSERT(status == OK);

  // Check cert chain after loading CA cert
  verify_cert(eid, &status, der_cert);
  CU_ASSERT(status == OK);

  X509_free(requestor_cert);
  EVP_PKEY_free(requestor_privkey);
}

void test_invalid_cert_chain_enclave(void)
{
  int ret;
  TableResponseStatus status;
  X509 *requestor_cert;
  uint64_t handle;
  unsigned char *der_buf = NULL;
  int der_len = -1;
  charbuf der_cert = new_charbuf(0);

  // load CA key to enclave
  ret = pelz_load_file_to_enclave((char *) "test/data/ca_pub.der.nkl", &handle);
  CU_ASSERT(ret == 0);
  add_cert_to_table(eid, &status, CA_TABLE, handle);
  CU_ASSERT(status == OK);

  // load cert from file
  BIO *cert_bio = BIO_new_file("test/data/node_pub.pem", "r");
  requestor_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
  BIO_free(cert_bio);

  // convert x509 to der format
  marshal_ec_x509_to_der(&requestor_cert, &der_buf, &der_len);
  der_cert.chars = der_buf;
  der_cert.len = der_len;

  // Check cert chain
  verify_cert(eid, &status, der_cert);
  CU_ASSERT(status != OK);

  X509_free(requestor_cert);
}
