//############################################################################
// aes_keywrap_test.c
//
// Tests for pelz AES keywrap functionality
//############################################################################

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>

#include "aes_keywrap_test.h"
#include <pelz_log.h>

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"

#define AES_KW_VECTOR_PATH "test/data/kwtestvectors"

//---------------------- AES Key Wrap Cipher Test Configuration --------------

//----------------------------------------------------------------------------
// aes_keywrap_suite_add_tests()
//----------------------------------------------------------------------------
int aes_keywrap_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test Pelz AES key wrap/unwrap parameter handling", test_aes_keywrap_parameters))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "Run AES key wrap test vectors", test_aes_keywrap_vectors))
  {
    return 1;
  }

  return 0;
}

//---------------------- AES Key Wrap Cipher Test Utilities --------------

//----------------------------------------------------------------------------
// convert_HexString_to_ByteArray()
//----------------------------------------------------------------------------
int convert_HexString_to_ByteArray(char **result, char *hex_str, int str_size)
{
  if ((str_size % 2) != 0)
  {
    fprintf(stderr, "ERROR: Invalid hex string size, must be even.\n");
    return 1;
  }

  size_t bufSize = ((str_size) / 2);
  char *buf = (char *) calloc(bufSize + 1, sizeof(char));

  for (int i = 0; i < (int) bufSize; i++)
  {
    sscanf(hex_str + (i * 2), "%02hhx", &buf[i]);
  }
  buf[bufSize] = '\0';

  *result = buf;

  return 0;
}

//----------------------------------------------------------------------------
// get_aes_keywrap_vector_from_file()
//----------------------------------------------------------------------------
int get_aes_keywrap_vector_from_file(FILE * fid,
  uint8_t ** K_vec,
  size_t * K_vec_len, uint8_t ** P_vec, size_t * P_vec_len, uint8_t ** C_vec, size_t * C_vec_len, bool * expect_pass)
{
  // create buffer to hold vector data read in from file a line at a time
  // specify buffer size to handle largest vector component (must include
  // some extra space for leading and/or trailing characters that get
  // stripped off)
  char buffer[MAX_TEST_VECTOR_COMPONENT_LENGTH];

  // create variables to buffer the components in a single test vector
  char *K_str;
  int K_str_len = 0;
  char *P_str;
  int P_str_len = 0;
  char *C_str;
  int C_str_len = 0;
  bool pass_result = true;      // unless vector has a 'FAIL' line, should pass

  K_str = (char *) calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  P_str = (char *) calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  C_str = (char *) calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);

  // create/initialize a counter to track progress (ensure that test vector
  // components are read and parsed in expected sequence)
  //     step = 1: searching for a 'K' vector component (start of test vector)
  //     step = 2: found a 'K' vector component
  //               expecting 'P', 'C' vector component
  //               finding another 'K' component in step 2 stays in step 2
  //     step = 3: have 'K' and either 'P' or 'C' vector components
  //               expecting 'P' or 'C' (whichever not yet found) or 'FAIL'
  //               finding another 'K' component in step 3 returns to step 2
  //     step = 4: found complete vector
  // any other parsing sequence values are invalid - failure or unexepected
  // file data at any step restarts the process (reset to first step)
  int step = 1;

  while ((!feof(fid)) && (step < 4))
  {
    // test vector file is read a line at a time until either EOF is reached
    // or a test vector grouping is successfully parsed.
    if (fgets(buffer, MAX_TEST_VECTOR_COMPONENT_LENGTH, fid) != NULL)
    {
      if (strncmp(buffer, "K = ", 4) == 0)
      {
        // If 'K = ' is found, we are at the start of a test vector
        // Note: regardless of incoming step level (< 4), finding 'K = ' puts
        //       the parsing process into step 2 (having 'K' but nothing else)
        step = 2;
        K_str_len = strlen(buffer) - 4; // strip leading 'K = ' sub-string
        memcpy(K_str, buffer + 4, K_str_len * sizeof(char));
        while ((K_str_len > 0) && ((K_str[K_str_len - 1] == '\n') || (K_str[K_str_len - 1] == '\r')))
        {
          K_str[--K_str_len] = '\0';  // strip any trailing '\n' or '\r'
        }
      }

      else if (strncmp(buffer, "P = ", 4) == 0)
      {
        // found 'P' vector component before 'K' - reset
        if ((step != 2) && (step != 3))
        {
          step = 1;
          P_str_len = 0;
          C_str_len = 0;
        }

        // correctly found 'P' component in step 2 or step 3
        else
        {
          step++;
          P_str_len = strlen(buffer) - 4; // strip leading 'P = ' sub-string
          memcpy(P_str, buffer + 4, P_str_len * sizeof(char));
          while ((P_str_len > 0) && ((P_str[P_str_len - 1] == '\n') || (P_str[P_str_len - 1] == '\r')))
          {
            P_str[--P_str_len] = '\0';  // strip any trailing '\n' or '\r'
          }
        }
      }

      else if (strncmp(buffer, "C = ", 4) == 0)
      {
        // found 'C' vector component before 'K' - reset
        if ((step != 2) && (step != 3))
        {
          step = 1;
          P_str_len = 0;
          C_str_len = 0;
        }

        // correctly found 'C' component in step 2 or step 3
        else
        {
          step++;
          C_str_len = strlen(buffer) - 4; // strip leading 'C = ' sub-string
          memcpy(C_str, buffer + 4, C_str_len * sizeof(char));
          while ((C_str_len > 0) && ((C_str[C_str_len - 1] == '\n') || (C_str[C_str_len - 1] == '\r')))
          {
            C_str[--C_str_len] = '\0';  // strip any trailing '\n' or '\r'
          }
        }
      }

      else if (strncmp(buffer, "FAIL", 4) == 0)
      {
        // found expected 'FAIL' result, but incomplete vector - reset
        if (step != 3)
        {
          step = 1;
          P_str_len = 0;
          C_str_len = 0;
        }

        // found expected 'FAIL' result (should be in place of 'P' component)
        else
        {
          step++;
          pass_result = false;
        }
      }

      // found line in vector file that is not in one of the formats parsed by
      // this function - reset (start over, looking for next vector)
      else
      {
        P_str_len = 0;
        C_str_len = 0;
        step = 1;
      }
    }
  }

  // reaching step 4 means a vector has been successfully parsed
  if (step == 4)
  {
    // use parsed results to populate output parameters
    convert_HexString_to_ByteArray((char **) K_vec, K_str, K_str_len);
    *K_vec_len = K_str_len / 2; // 2 hex chars map to a byte of key
    convert_HexString_to_ByteArray((char **) P_vec, P_str, P_str_len);
    *P_vec_len = P_str_len / 2; // 2 hex chars map to a byte of key
    convert_HexString_to_ByteArray((char **) C_vec, C_str, C_str_len);
    *C_vec_len = C_str_len / 2; // 2 hex chars map to a byte of key
    *expect_pass = pass_result;
  }

  // clean-up allocated memory
  free(K_str);
  free(P_str);
  free(C_str);

  // if while loop exit due to EOF, return unsuccessful result
  if (step != 4)
  {
    return 1;
  }

  // normal termination
  return 0;
}

//---------------------- AES Key Wrap Cipher Tests ---------------------------

//----------------------------------------------------------------------------
// test_aes_keywrap_parameters()
//----------------------------------------------------------------------------
void test_aes_keywrap_parameters(void)
{
  unsigned char *key = NULL;
  int key_len = 0;

  unsigned char *inData = NULL;
  size_t inData_len = 0;

  unsigned char *outData = NULL;
  size_t outData_len = 0;

  int ret;

  pelz_log(LOG_DEBUG, "Start AES Key Wrap Parameters Test");
  // Test failure on null key
  inData = (unsigned char *) malloc(16);
  inData_len = 16;
  key_len = 16;
  test_aes_keywrap_3394nopad_encrypt(eid, &ret, key_len, key, inData_len, inData, &outData_len, &outData);
  CU_ASSERT(ret == 1);
  CU_ASSERT((outData == NULL) && (outData_len == 0));
  pelz_log(LOG_DEBUG, "Output Len: %lu; Output: %s", outData_len, outData);
  test_aes_keywrap_3394nopad_decrypt(eid, &ret, key_len, key, inData_len, inData, &outData_len, &outData);
  CU_ASSERT(ret == 1);
  CU_ASSERT((outData == NULL) && (outData_len == 0));
  pelz_log(LOG_DEBUG, "Output Len: %lu; Output: %s", outData_len, outData);

  // Test failure on key of length 0
  key = (unsigned char *) malloc(16);
  key_len = 0;
  test_aes_keywrap_3394nopad_encrypt(eid, &ret, key_len, key, inData_len, inData, &outData_len, &outData);
  CU_ASSERT(ret == 1);
  CU_ASSERT((outData == NULL) && (outData_len == 0));
  test_aes_keywrap_3394nopad_decrypt(eid, &ret, key_len, key, inData_len, inData, &outData_len, &outData);
  CU_ASSERT(ret == 1);
  CU_ASSERT((outData == NULL) && (outData_len == 0));
  // Test failure on input data of length 0
  key_len = 16;
  inData_len = 0;
  test_aes_keywrap_3394nopad_encrypt(eid, &ret, key_len, key, inData_len, inData, &outData_len, &outData);
  CU_ASSERT(ret == 1);
  CU_ASSERT((outData == NULL) && (outData_len == 0));
  test_aes_keywrap_3394nopad_decrypt(eid, &ret, key_len, key, inData_len, inData, &outData_len, &outData);
  CU_ASSERT(ret == 1);
  CU_ASSERT((outData == NULL) && (outData_len == 0));
  // Test failure with input data too short
  inData_len = 8;
  test_aes_keywrap_3394nopad_encrypt(eid, &ret, key_len, key, inData_len, inData, &outData_len, &outData);
  CU_ASSERT(ret == 1);
  CU_ASSERT((outData == NULL) && (outData_len == 0));
  test_aes_keywrap_3394nopad_decrypt(eid, &ret, key_len, key, inData_len, inData, &outData_len, &outData);
  CU_ASSERT(ret == 1);
  CU_ASSERT((outData == NULL) && (outData_len == 0));
  // Test failure with input data that's not a multiple of 8 bytes long
  inData_len = 17;
  test_aes_keywrap_3394nopad_encrypt(eid, &ret, key_len, key, inData_len, inData, &outData_len, &outData);
  CU_ASSERT(ret == 1);
  CU_ASSERT((outData == NULL) && (outData_len == 0));
  test_aes_keywrap_3394nopad_decrypt(eid, &ret, key_len, key, inData_len, inData, &outData_len, &outData);
  CU_ASSERT(ret == 1);
  CU_ASSERT((outData == NULL) && (outData_len == 0));
  free(key);
  free(inData);
}

//----------------------------------------------------------------------------
// test_aes_keywrap_vectors()
//----------------------------------------------------------------------------
void test_aes_keywrap_vectors(void)
{
  // specify the compilation of test vector mappings for kmyth AES GCM
  // decrypt cipher testing.
  pelz_log(LOG_DEBUG, "Start AES Key Wrap Vetors Test");
  const cipher_vector_compilation aes_keywrap_vectors = {
    .count = 6,.sets = {
        {
          .desc = "AES-128, RFC-3394 Key Wrap no padding (KW-AE), forward",.func_to_test =
            "test_aes_keywrap_3394nopad_encrypt",.path = "./test/data/kwtestvectors/KW_AE_128.txt"},
        {
          .desc = "AES-128, RFC-3394 Key Unwrap no padding (KW-AD), forward",.func_to_test =
            "test_aes_keywrap_3394nopad_encrypt",.path = "./test/data/kwtestvectors/KW_AD_128.txt"},
        {
          .desc = "AES-192, RFC-3394 Key Wrap no padding (KW-AE), forward",.func_to_test =
            "test_aes_keywrap_3394nopad_encrypt",.path = "./test/data/kwtestvectors/KW_AE_192.txt"},
        {
          .desc = "AES-192, RFC-3394 Key Unwrap no padding (KW-AD), forward",.func_to_test =
            "test_aes_keywrap_3394nopad_encrypt",.path = "./test/data/kwtestvectors/KW_AD_192.txt"},
        {
          .desc = "AES-256, RFC-3394 Key Wrap no padding (KW-AE), forward",.func_to_test =
            "test_aes_keywrap_3394nopad_encrypt",.path = "./test/data/kwtestvectors/KW_AE_256.txt"},
        {
        .desc = "AES-256, RFC-3394 Key Unwrap no padding (KW-AD), forward",.func_to_test =
            "test_aes_keywrap_3394nopad_encrypt",.path = "./test/data/kwtestvectors/KW_AD_256.txt"},}
  };
  // array of file pointers for test vector files
  FILE *test_vector_fd[MAX_VECTOR_SETS_IN_COMPILATION] = {
    NULL
  };
  // check that number of test vector files complies with specified maximum
  if (aes_keywrap_vectors.count > MAX_VECTOR_SETS_IN_COMPILATION)
  {
    CU_FAIL("AES Key Wrap Test Vector File Count Exceeds Limit");
    return;
  }

  // create counters to track the number of:
  //   - configured test vector files parsed (partially or fully)
  //   - test vectors applied (cumulative count)
  size_t parsed_test_vector_files = 0;
  size_t cumulative_test_vector_count = 0;

  // allocate memory to hold a single test vector - re-use these buffers
  // for all test vectors used during these tests
  unsigned char *key_data;
  size_t key_data_len = 0;
  unsigned char *pt_data;
  size_t pt_data_len = 0;
  unsigned char *ct_data;
  size_t ct_data_len = 0;
  bool result_bool = false;

  key_data = (unsigned char *) calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  pt_data = (unsigned char *) calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  ct_data = (unsigned char *) calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  for (int i = 0; i < (int) aes_keywrap_vectors.count; i++)
  {
    // open test vector file
    test_vector_fd[i] = fopen(aes_keywrap_vectors.sets[i].path, "r");
    if (test_vector_fd[i] != NULL)
    {
      // counter to track number of test vectors applied from this file
      int test_vector_count = 0;

      // flag used to signal stop processing test vector file
      //   - invalid kmyth "function to test" associated with vector set
      //   - EOF reached (get_aes_keywrap_vector_from_file() failed)
      //   - test count limit exceeded
      bool done_with_test_vector_file = false;

      while (!done_with_test_vector_file)
      {
        // Parse next vector from file
        if (get_aes_keywrap_vector_from_file(test_vector_fd[i],
            &key_data, &key_data_len, &pt_data, &pt_data_len, &ct_data, &ct_data_len, &result_bool) == 0)
        {
          // Create a new buffer to hold the result for each vector applied
          unsigned char *out;
          size_t out_len = 0;

          out = (unsigned char *) calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
          // increment count of test vectors applied and test if limit reached
          // if the test vector count limit is reached, this will be the last
          // test vector retrieved from this file and parsed
          test_vector_count++;
          if (test_vector_count > MAX_KEYWRAP_TEST_VECTOR_COUNT)
          {
            done_with_test_vector_file = true;
          }

          // create variable to hold response code from function being tested
          int rc = -1;

          // create pointers to applicable result (i.e., ct_data and
          // ct_data_len for encrypt, pt_data and pt_data_len for decrypt)
          unsigned char *exp_result = NULL;
          size_t exp_result_len = 0;

          if (strncmp(aes_keywrap_vectors.sets[i].func_to_test, "test_aes_keywrap_3394nopad_encrypt", 29) == 0)
          {
            test_aes_keywrap_3394nopad_encrypt(eid, &rc, key_data_len, key_data, pt_data_len, pt_data, &out_len, &out);
            exp_result = ct_data;
            exp_result_len = ct_data_len;
          }
          else if (strncmp(aes_keywrap_vectors.sets[i].func_to_test, "test_aes_keywrap_3394nopad_decrypt", 29) == 0)
          {
            test_aes_keywrap_3394nopad_decrypt(eid, &rc, key_data_len, key_data, ct_data_len, ct_data, &out_len, &out);
            exp_result = pt_data;
            exp_result_len = pt_data_len;
          }
          else
          {
            CU_FAIL("Test vector file linked to invalid function to test");
            // don't get any more vectors from this file - can't apply them
            done_with_test_vector_file = true;
          }

          // consolidate results of applying test vector into a single assertion
          // create flag to aggregate pass/fail result
          // (initialize true but latch in false for any unexpected result)
          bool vector_passed = true;

          if (rc != -1)
          {
            if (result_bool == false)
            {
              // check if a test vector expected to fail, passed
              if (rc == 0)
              {
                vector_passed = false;
              }
            }
            else
            {
              // check if a test vector expected to pass, failed
              if (rc != 0)
              {
                vector_passed = false;
              }

              // check for unexpected size of decrypted result
              if (out_len != exp_result_len)
              {
                vector_passed = false;
              }

              // check that expected result matches (byte for byte)
              for (int j = 0; j < (int) out_len; j++)
              {
                if (out[j] != exp_result[j])
                {
                  vector_passed = false;
                }
              }
            }
            CU_ASSERT(vector_passed);
            // clean-up output_data byte array
            if (rc == 0)
            {
              free(out);
            }
          }
          else
          {
            CU_FAIL("Test vector was not applied");
          }
        }

        else
        {
          // get_aes_gcm_test_vector_from_file() returned error - must be EOF
          done_with_test_vector_file = true;
        }
      }

      // Done with the test vector file (processed all vectors or reached max)
      fclose(test_vector_fd[i]);
      // update test vector tracking counters
      parsed_test_vector_files++;
      cumulative_test_vector_count += test_vector_count;
    }
  }

  // print message to inform about optional tests run
  pelz_log(LOG_DEBUG, "INFO: %ld of %ld optional AES keywrap test vector files parsed",
    parsed_test_vector_files, aes_keywrap_vectors.count);
  if (cumulative_test_vector_count > 0)
  {
    pelz_log(LOG_DEBUG, "%ld test vectors applied", cumulative_test_vector_count);
  }

  // clean-up allocated test vector memory
  free(key_data);
  free(pt_data);
  free(ct_data);
}
