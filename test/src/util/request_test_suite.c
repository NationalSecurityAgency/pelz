/*
 * request_test_suite.c
 */

#include "request_test_suite.h"
#include "test_helper_functions.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cjson/cJSON.h>

#include <charbuf.h>
#include <pelz_log.h>
#include <common_table.h>
#include <pelz_request_handler.h>

#include <openssl/x509.h>
#include <openssl/pem.h>

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "test_enclave_u.h"
#include "request_test_helpers.h"
#include "kmyth/formatting_tools.h"
#include "ca_table.h"
#include "pelz_loaders.h"

static const char* cipher_names[] = {"AES/KeyWrap/RFC3394NoPadding/256",
				     "AES/KeyWrap/RFC3394NoPadding/192",
				     "AES/KeyWrap/RFC3394NoPadding/128",
				     "AES/GCM/NoPadding/256",
				     "AES/GCM/NoPadding/192",
				     "AES/GCM/NoPadding/128",
				     NULL};

// Bit of a kludge, we need the correct key lengths to test the
// encrypt/decrypt cycle, but the code to extract them from the cipher
// is only built in the enclave.
static const size_t cipher_key_bytes[] = {32, 24, 16, 32, 24, 16, 0};

// Adds all request handler tests to main test runner.
int request_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test Pelz Request Invalid Key ID", test_invalid_key_id))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Pelz Encrypt/Decrypt", test_encrypt_decrypt))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test Pelz Request Missing Key ID", test_missing_key_id))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test Pelz Request Invalid or Missing Cipher Name", test_invalid_cipher_name))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test Pelz Request Missing Input Data", test_missing_input_data))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test Pelz Signed Request Handling", test_signed_request_handling))
  {
    return 1;
  }
  return (0);
}

void test_invalid_key_id(void)
{
  pelz_log(LOG_DEBUG, "Start Invalid Key ID Test");
  TableResponseStatus table_status;
  RequestResponseStatus response_status;

  // Wipe out the key table in case any other test didn't clean
  // itself up appropriately.
  table_destroy(eid, &table_status, KEY);

  const char* key_id_str = "file:/test/data/key1.txt";
  charbuf key_id = new_charbuf(strlen(key_id_str));
  memcpy(key_id.chars, key_id_str, key_id.len);

  charbuf signature = new_charbuf(0);
  charbuf cert = new_charbuf(0);
  
  size_t cipher_index = 0;
  while(cipher_names[cipher_index] != NULL)
  {
    const char* plaintext_str = "abcdefghijklmnopqrstuvwxyz012345";
    charbuf plaintext = new_charbuf(strlen(plaintext_str));
    memcpy(plaintext.chars, plaintext_str, plaintext.len);

    charbuf cipher_name = new_charbuf(strlen(cipher_names[cipher_index]));
    memcpy(cipher_name.chars, cipher_names[cipher_index], cipher_name.len);
    cipher_index++;
    
    charbuf ciphertext = new_charbuf(0);
    charbuf iv = new_charbuf(0);
    charbuf tag = new_charbuf(0);

    pelz_encrypt_request_handler(eid, &response_status, REQ_ENC, key_id, cipher_name, plaintext, &ciphertext, &iv, &tag, signature, cert);
    CU_ASSERT(response_status == KEK_NOT_LOADED);
    CU_ASSERT(ciphertext.chars == NULL);
    CU_ASSERT(ciphertext.len == 0);
    CU_ASSERT(iv.chars == NULL);
    CU_ASSERT(iv.len == 0);
    CU_ASSERT(tag.chars == NULL);
    CU_ASSERT(tag.len == 0);

    free_charbuf(&ciphertext);
    free_charbuf(&iv);
    free_charbuf(&tag);
    free_charbuf(&plaintext);

    pelz_decrypt_request_handler(eid, &response_status, REQ_DEC, key_id, cipher_name, ciphertext, iv, tag, &plaintext, signature, cert);
    CU_ASSERT(response_status == KEK_NOT_LOADED);
    CU_ASSERT(plaintext.chars == NULL);
    CU_ASSERT(plaintext.len == 0);

    free_charbuf(&cipher_name);
    free_charbuf(&ciphertext);
    free_charbuf(&iv);
    free_charbuf(&tag);
    free_charbuf(&plaintext);
  }
  table_destroy(eid, &table_status, KEY);
  free_charbuf(&key_id);
  free_charbuf(&signature);
  free_charbuf(&cert);
  pelz_log(LOG_DEBUG, "Finish Invalid Key ID Test");
}

void test_encrypt_decrypt(void)
{
  pelz_log(LOG_DEBUG, "Start Encrypt/Decrypt Test");
  RequestResponseStatus request_status;
  TableResponseStatus table_status;

  const char* key_id_str = "file:/test/data/key1.txt";
  charbuf key_id = new_charbuf(strlen(key_id_str));
  memcpy(key_id.chars, key_id_str, key_id.len);

  const char*  full_key_data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

  const char* plaintext_str = "abcdefghijklmnopqrstuvwxyz012345";
  charbuf plaintext = new_charbuf(strlen(plaintext_str));
  memcpy(plaintext.chars, plaintext_str, plaintext.len);

  size_t cipher_index = 0;
  while(cipher_names[cipher_index] != NULL)
  {
    charbuf cipher_name = new_charbuf(strlen(cipher_names[cipher_index]));
    memcpy(cipher_name.chars, cipher_names[cipher_index], cipher_name.len);

    charbuf key_data = new_charbuf(cipher_key_bytes[cipher_index]);
    memcpy(key_data.chars, full_key_data, key_data.len);
    cipher_index++;

    key_table_add_key(eid, &table_status, key_id, key_data);
    free_charbuf(&key_data);
    
    charbuf iv = new_charbuf(0);
    charbuf tag = new_charbuf(0);
    charbuf ciphertext = new_charbuf(0);
    charbuf decrypt = new_charbuf(0);
    charbuf signature = new_charbuf(0);
    charbuf cert = new_charbuf(0);

    pelz_log(LOG_DEBUG, "Plaintext: %ld, %.*s", plaintext.len, plaintext.len, plaintext.chars);
    pelz_encrypt_request_handler(eid, &request_status, REQ_ENC, key_id, cipher_name, plaintext, &ciphertext, &iv, &tag, signature, cert);
    CU_ASSERT(request_status == REQUEST_OK);
    pelz_log(LOG_DEBUG, "Request Status: %d", request_status);
    pelz_log(LOG_DEBUG, "Plaintext: %ld, %.*s", plaintext.len, plaintext.len, plaintext.chars);
    pelz_log(LOG_DEBUG, "Ciphertext Lenght: %ld", ciphertext.len);

    pelz_decrypt_request_handler(eid, &request_status, REQ_DEC, key_id, cipher_name, ciphertext, iv, tag, &decrypt, signature, cert);
    CU_ASSERT(request_status == REQUEST_OK);
    CU_ASSERT(decrypt.len == plaintext.len);
    CU_ASSERT(memcmp(decrypt.chars, plaintext.chars, decrypt.len) == 0);
    
    free_charbuf(&iv);
    free_charbuf(&tag);
    free_charbuf(&ciphertext);
    free_charbuf(&decrypt);
    free_charbuf(&cipher_name);
    table_destroy(eid, &table_status, KEY);
  }
  
  free_charbuf(&plaintext);
  free_charbuf(&key_id);
  pelz_log(LOG_DEBUG, "Finish Encrypt/Decrypt Test");
}

void test_missing_key_id(void)
{
  pelz_log(LOG_DEBUG, "Start Missing Key ID Test");
  RequestResponseStatus request_status;

  charbuf key_id = new_charbuf(0);

  const char* plaintext_str = "abcdefghijklmnopqrstuvwxyz012345";
  charbuf plaintext = new_charbuf(strlen(plaintext_str));
  memcpy(plaintext.chars, plaintext_str, plaintext.len);

  size_t cipher_index = 0;
  while(cipher_names[cipher_index] != NULL)
  {
    charbuf cipher_name = new_charbuf(strlen(cipher_names[cipher_index]));
    memcpy(cipher_name.chars, cipher_names[cipher_index], cipher_name.len);
    cipher_index++;
    
    charbuf iv = new_charbuf(0);
    charbuf tag = new_charbuf(0);
    charbuf ciphertext = new_charbuf(0);
    charbuf signature = new_charbuf(0);
    charbuf cert = new_charbuf(0);
    
    pelz_encrypt_request_handler(eid, &request_status, REQ_ENC, key_id, cipher_name, plaintext, &ciphertext, &iv, &tag, signature, cert);
    CU_ASSERT(request_status == ENCRYPT_ERROR);
    CU_ASSERT(iv.chars == NULL);
    CU_ASSERT(iv.len == 0);
    CU_ASSERT(tag.chars == NULL);
    CU_ASSERT(tag.len == 0);
    CU_ASSERT(ciphertext.chars == NULL);
    CU_ASSERT(ciphertext.len == 0);
    
    free_charbuf(&iv);
    free_charbuf(&tag);
    free_charbuf(&ciphertext);
    

    // For testing purposes we use "plaintext" as the ciphertext,
    // since the code should never look at it anyway.
    pelz_decrypt_request_handler(eid, &request_status, REQ_DEC, key_id, cipher_name, plaintext, iv, tag, &ciphertext, signature, cert);
    CU_ASSERT(request_status == DECRYPT_ERROR);
    CU_ASSERT(iv.chars == NULL);
    CU_ASSERT(iv.len == 0);
    CU_ASSERT(tag.chars == NULL);
    CU_ASSERT(tag.len == 0);
    CU_ASSERT(ciphertext.chars == NULL);
    CU_ASSERT(ciphertext.len == 0);
    
    free_charbuf(&iv);
    free_charbuf(&tag);
    free_charbuf(&ciphertext);
    
    free_charbuf(&cipher_name);
  }
  
  free_charbuf(&plaintext);
  free_charbuf(&key_id);
  pelz_log(LOG_DEBUG, "Finish Missing Key ID Test");
}

void test_invalid_cipher_name(void)
{
  pelz_log(LOG_DEBUG, "Start Invalid Cipher Name Test");
  RequestResponseStatus request_status;
  TableResponseStatus table_status;

  table_destroy(eid, &table_status, KEY);

  const char* key_id_str = "file:/test/data/key1.txt";
  charbuf key_id = new_charbuf(strlen(key_id_str));
  memcpy(key_id.chars, key_id_str, key_id.len);

  const char*  full_key_data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

  const char* plaintext_str = "abcdefghijklmnopqrstuvwxyz012345";
  charbuf plaintext = new_charbuf(strlen(plaintext_str));
  memcpy(plaintext.chars, plaintext_str, plaintext.len);

  // We add a key to the table, although we shouldn't need it
  charbuf key_data = new_charbuf(32);
  memcpy(key_data.chars, full_key_data, key_data.len);
  key_table_add_key(eid, &table_status, key_id, key_data);

     
  charbuf iv = new_charbuf(0);
  charbuf tag = new_charbuf(0);
  charbuf ciphertext = new_charbuf(0);
  charbuf decrypt = new_charbuf(0);
  charbuf signature = new_charbuf(0);
  charbuf cert = new_charbuf(0);
  // Test with an empty cipher name
  charbuf cipher_name = new_charbuf(0);
  
  pelz_encrypt_request_handler(eid, &request_status, REQ_ENC, key_id, cipher_name, plaintext, &ciphertext, &iv, &tag, signature, cert);
  CU_ASSERT(request_status == ENCRYPT_ERROR);
  CU_ASSERT(iv.chars == NULL);
  CU_ASSERT(iv.len == 0);
  CU_ASSERT(tag.chars == NULL);
  CU_ASSERT(tag.len == 0);
  CU_ASSERT(ciphertext.chars == NULL);
  CU_ASSERT(ciphertext.len == 0);

  // Repurpose plaintext as ciphertext, which shouldn't matter
  // since it should never get looked at.
  pelz_decrypt_request_handler(eid, &request_status, REQ_DEC, key_id, cipher_name, plaintext, iv, tag, &ciphertext, signature, cert);
  CU_ASSERT(request_status == DECRYPT_ERROR);
  CU_ASSERT(iv.chars == NULL);
  CU_ASSERT(iv.len == 0);
  CU_ASSERT(tag.chars == NULL);
  CU_ASSERT(tag.len == 0);
  CU_ASSERT(ciphertext.chars == NULL);
  CU_ASSERT(ciphertext.len == 0);


  // Now we test with an invalid (but non-empty) cipher name
  const char* cipher_name_str = "fakeciphername";
  cipher_name = new_charbuf(strlen(cipher_name_str));
  memcpy(cipher_name.chars, cipher_name_str, strlen(cipher_name_str));
  pelz_encrypt_request_handler(eid, &request_status, REQ_ENC, key_id, cipher_name, plaintext, &ciphertext, &iv, &tag, signature, cert);
  CU_ASSERT(request_status == ENCRYPT_ERROR);
  CU_ASSERT(iv.chars == NULL);
  CU_ASSERT(iv.len == 0);
  CU_ASSERT(tag.chars == NULL);
  CU_ASSERT(tag.len == 0);
  CU_ASSERT(ciphertext.chars == NULL);
  CU_ASSERT(ciphertext.len == 0);

  // Repurpose plaintext as ciphertext, which shouldn't matter
  // since it should never get looked at.
  pelz_decrypt_request_handler(eid, &request_status, REQ_DEC, key_id, cipher_name, plaintext, iv, tag, &ciphertext, signature, cert);
  CU_ASSERT(request_status == DECRYPT_ERROR);
  CU_ASSERT(iv.chars == NULL);
  CU_ASSERT(iv.len == 0);
  CU_ASSERT(tag.chars == NULL);
  CU_ASSERT(tag.len == 0);
  CU_ASSERT(ciphertext.chars == NULL);
  CU_ASSERT(ciphertext.len == 0);
  
  free_charbuf(&iv);
  free_charbuf(&tag);
  free_charbuf(&ciphertext);
  free_charbuf(&decrypt);
  free_charbuf(&cipher_name);
  table_destroy(eid, &table_status, KEY);
  free_charbuf(&plaintext);
  free_charbuf(&key_id);
  free_charbuf(&key_data);
  pelz_log(LOG_DEBUG, "Finish Invalid Cipher Name Test");
}


void test_missing_input_data(void)
{
  pelz_log(LOG_DEBUG, "Start Missing Input Data Test");
  RequestResponseStatus request_status;
  TableResponseStatus table_status;

  const char* key_id_str = "file:/test/data/key1.txt";
  charbuf key_id = new_charbuf(strlen(key_id_str));
  memcpy(key_id.chars, key_id_str, key_id.len);

  const char*  full_key_data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

  charbuf plaintext = new_charbuf(0);

  size_t cipher_index = 0;
  while(cipher_names[cipher_index] != NULL)
  {
    charbuf cipher_name = new_charbuf(strlen(cipher_names[cipher_index]));
    memcpy(cipher_name.chars, cipher_names[cipher_index], cipher_name.len);

    charbuf key_data = new_charbuf(cipher_key_bytes[cipher_index]);
    memcpy(key_data.chars, full_key_data, key_data.len);
    cipher_index++;

    key_table_add_key(eid, &table_status, key_id, key_data);
    free_charbuf(&key_data);
    
    charbuf iv = new_charbuf(0);
    charbuf tag = new_charbuf(0);
    charbuf output_data = new_charbuf(0);
    charbuf signature = new_charbuf(0);
    charbuf cert = new_charbuf(0);
    
    pelz_encrypt_request_handler(eid, &request_status, REQ_ENC, key_id, cipher_name, plaintext, &output_data, &iv, &tag, signature, cert);
    CU_ASSERT(request_status == ENCRYPT_ERROR);
    CU_ASSERT(output_data.chars == NULL);
    CU_ASSERT(output_data.len == 0);
    CU_ASSERT(iv.chars == NULL);
    CU_ASSERT(iv.len == 0);
    CU_ASSERT(tag.chars == NULL);
    CU_ASSERT(tag.len == 0);

    pelz_decrypt_request_handler(eid, &request_status, REQ_DEC, key_id, cipher_name, plaintext, iv, tag, &output_data, signature, cert);
    CU_ASSERT(request_status == DECRYPT_ERROR);
    CU_ASSERT(output_data.chars == NULL);
    CU_ASSERT(output_data.len == 0);
    CU_ASSERT(iv.chars == NULL);
    CU_ASSERT(iv.len == 0);
    CU_ASSERT(tag.chars == NULL);
    CU_ASSERT(tag.len == 0);
    
    free_charbuf(&iv);
    free_charbuf(&tag);
    free_charbuf(&output_data);
    free_charbuf(&cipher_name);
    table_destroy(eid, &table_status, KEY);
  }
  
  free_charbuf(&plaintext);
  free_charbuf(&key_id);
  pelz_log(LOG_DEBUG, "Finish Missing Input Data Test");
}

void test_signed_request_handling(void)
{
  pelz_log(LOG_DEBUG, "Start Signed Request Handling Test");
  TableResponseStatus table_status;
  RequestResponseStatus response_status;

  // Wipe out the key table in case any other test didn't clean
  // itself up appropriately.
  table_destroy(eid, &table_status, KEY);

  const char* key_id_str = "file:/test/data/key1.txt";
  charbuf key_id = new_charbuf(strlen(key_id_str));
  memcpy(key_id.chars, key_id_str, key_id.len);

  const char*  full_key_data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  charbuf key_data = new_charbuf(cipher_key_bytes[0]);
  memcpy(key_data.chars, full_key_data, key_data.len);
  key_table_add_key(eid, &table_status, key_id, key_data);
  
  const char* data_str = "abcdefghijklmnopqrstuvwxyz012345";
  charbuf data = new_charbuf(strlen(data_str));
  memcpy(data.chars, data_str, data.len);

  charbuf iv = new_charbuf(0);
  charbuf tag = new_charbuf(0);

  BIO *cert_bio = BIO_new_file("test/data/worker_pub.pem", "r");
  BIO *key_bio = BIO_new_file("test/data/worker_priv.pem", "r");

  X509* requestor_cert_x509 = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
  BIO_free(cert_bio);

  EVP_PKEY* requestor_privkey = PEM_read_bio_PrivateKey(key_bio, NULL, 0, NULL);
  BIO_free(key_bio);

  // Convert X509 version certificate to DER
  charbuf der;
  charbuf output;
  charbuf cipher_data;

  int der_len = i2d_X509(requestor_cert_x509, &(der.chars));
  if(der_len < 0)
  {
    CU_ASSERT(0);
    return;
  }
  der.len = (size_t)der_len;

  charbuf cipher_name = new_charbuf(strlen(cipher_names[0]));
  memcpy(cipher_name.chars, cipher_names[0], cipher_name.len);

  // Generate encrypt signature
  charbuf enc_signature = sign_request(REQ_ENC_SIGNED, key_id, cipher_name, data, iv, tag, der, requestor_privkey);

  // Generate decrypt cipher data
  pelz_encrypt_request_handler(eid, &response_status, REQ_ENC, key_id, cipher_name, data, &output, &iv, &tag, enc_signature, der);
  cipher_data = copy_chars_from_charbuf(output, 0);
  free_charbuf(&output);

  // Generate decrypt signature
  charbuf dec_signature = sign_request(REQ_DEC_SIGNED, key_id, cipher_name, cipher_data, iv, tag, der, requestor_privkey);

  // Test with cert whose signature doesn't match any known authority
  pelz_encrypt_request_handler(eid, &response_status, REQ_ENC_SIGNED, key_id, cipher_name, data, &output, &iv, &tag, enc_signature, der);
  CU_ASSERT(response_status == SIGNATURE_ERROR);
  pelz_decrypt_request_handler(eid, &response_status, REQ_DEC_SIGNED, key_id, cipher_name, cipher_data, iv, tag, &output, dec_signature, der);
  CU_ASSERT(response_status == SIGNATURE_ERROR)

  // Add an authority to the CA table
  uint64_t handle;
  pelz_load_file_to_enclave((char*)"test/data/ca_pub.der.nkl", &handle);
  add_cert_to_table(eid, &table_status, CA_TABLE, handle);

  // Test a good signature for encrypt
  pelz_encrypt_request_handler(eid, &response_status, REQ_ENC_SIGNED, key_id, cipher_name, data, &output, &iv, &tag, enc_signature, der);
  CU_ASSERT(response_status == REQUEST_OK);
  CU_ASSERT(output.len == cipher_data.len);
  CU_ASSERT(memcmp(output.chars, cipher_data.chars, output.len) == 0);
  free_charbuf(&output);

  // Test a good signature for decrypt
  pelz_decrypt_request_handler(eid, &response_status, REQ_DEC_SIGNED, key_id, cipher_name, cipher_data, iv, tag, &output, dec_signature, der);
  CU_ASSERT(response_status == REQUEST_OK);
  CU_ASSERT(output.len == data.len);
  CU_ASSERT(memcmp(output.chars, data.chars, output.len) == 0);
  free_charbuf(&output);

  // Test with an invalid thing for the cert
  pelz_encrypt_request_handler(eid, &response_status, REQ_ENC_SIGNED, key_id, cipher_name, data, &output, &iv, &tag, enc_signature, enc_signature);
  CU_ASSERT(response_status == SIGNATURE_ERROR);

  // Test with an invalid thing for the cert
  pelz_decrypt_request_handler(eid, &response_status, REQ_DEC_SIGNED, key_id, cipher_name, cipher_data, iv, tag, &output, dec_signature, dec_signature);
  CU_ASSERT(response_status == SIGNATURE_ERROR)

  // Test with a signature that should fail
  pelz_encrypt_request_handler(eid, &response_status, REQ_ENC_SIGNED, key_id, cipher_name, data, &output, &iv, &tag, der, der);
  CU_ASSERT(response_status == SIGNATURE_ERROR);

  // Test with a signature that should fail
  pelz_decrypt_request_handler(eid, &response_status, REQ_DEC_SIGNED, key_id, cipher_name, cipher_data, iv, tag, &output, der, der);
  CU_ASSERT(response_status == SIGNATURE_ERROR)
  
  table_destroy(eid, &table_status, KEY);
  table_destroy(eid, &table_status, CA_TABLE);
  free_charbuf(&output);
  free_charbuf(&iv);
  free_charbuf(&tag);
  free_charbuf(&enc_signature);
  free_charbuf(&dec_signature);
  free_charbuf(&cipher_name);
  free_charbuf(&der);
  free_charbuf(&key_id);
  free_charbuf(&data);
  free_charbuf(&cipher_data);
  X509_free(requestor_cert_x509);
  EVP_PKEY_free(requestor_privkey);
  free_charbuf(&key_data);
  pelz_log(LOG_DEBUG, "Finish Signed Request Handling Test");
}
