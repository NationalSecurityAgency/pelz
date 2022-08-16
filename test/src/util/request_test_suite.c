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

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "test_enclave_u.h"

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
  return (0);
}

void test_invalid_key_id(void)
{
  TableResponseStatus table_status;
  RequestResponseStatus response_status;

  // Wipe out the key table in case any other test didn't clean
  // itself up appropriately.
  table_destroy(eid, &table_status, KEY);

  const char* key_id_str = "file:/test/data/key1.txt";
  charbuf key_id = new_charbuf(strlen(key_id_str));
  memcpy(key_id.chars, key_id_str, key_id.len);

  charbuf plaintext;
  charbuf ciphertext;
  charbuf iv;
  charbuf tag;
  charbuf signature;
  charbuf cert;
  
  size_t cipher_index = 0;
  while(cipher_names[cipher_index] != NULL)
  {
    charbuf cipher_name = new_charbuf(strlen(cipher_names[cipher_index]));
    memcpy(cipher_name.chars, cipher_names[cipher_index], cipher_name.len);
    cipher_index++;
    
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

    pelz_decrypt_request_handler(eid, &response_status, REQ_DEC, key_id, cipher_name, ciphertext, iv, tag, &plaintext, signature, cert);
    CU_ASSERT(response_status == KEK_NOT_LOADED);
    CU_ASSERT(plaintext.chars == NULL);
    CU_ASSERT(plaintext.len == 0);

    free_charbuf(&cipher_name);
  }
  table_destroy(eid, &table_status, KEY);
  free_charbuf(&key_id);
}

void test_encrypt_decrypt(void)
{
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
    pelz_encrypt_request_handler(eid, &request_status, REQ_ENC, key_id, cipher_name, plaintext, &ciphertext, &iv, &tag, signature, cert);
    CU_ASSERT(request_status == REQUEST_OK);

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
}

void test_missing_key_id(void)
{
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
}

void test_invalid_cipher_name(void)
{
  RequestResponseStatus request_status;
  TableResponseStatus table_status;

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
}


void test_missing_input_data(void)
{
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
}
