/*
 * seal.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <kmyth/kmyth.h>
#include <kmyth/file_io.h>

#include "pelz_log.h"
#include "seal.h"
#include "test_seal.h"

#include "pelz_enclave.h"
#include "sgx_seal_unseal_impl.h"

#define ENCLAVE_PATH "sgx/pelz_test_enclave.signed.so"

int seal_for_testing(char *filename, char **outpath, size_t outpath_size, bool tpm)
{
  uint8_t *data = NULL;
  size_t data_len = 0;
  uint8_t *sgx_seal = NULL;
  size_t sgx_seal_len = 0;
  uint8_t *tpm_seal = NULL;
  size_t tpm_seal_len = 0;

  pelz_log(LOG_DEBUG, "Seal function");
  //Validating filename and data from file
  if (read_validate(filename, &data, &data_len))
  {
    return 1;          
  }

  //SGX sealing of data in nkl format
  if (seal_nkl_for_testing(data, data_len, &sgx_seal, &sgx_seal_len))
  {
    free(data);
    return 1;    
  }
  free(data);

  //Checking if TPM seal is requested
  if (tpm)
  {
    //TPM sealing of data in ski format
    if (seal_ski(sgx_seal, sgx_seal_len, &tpm_seal, &tpm_seal_len))
    {
      free(sgx_seal);
      return 1;
    }
    free(sgx_seal);
  }

  //Checking and/or setting output path
  if (outpath_validate(filename, outpath, outpath_size, tpm))
  {
    return 1;
  }

  //Write bytes to file based on outpath
  if (tpm)
  {
    pelz_log(LOG_DEBUG, "Write file to .ski");
    if (write_bytes_to_file(*outpath, tpm_seal, tpm_seal_len))
    {
      pelz_log(LOG_ERR, "error writing data to .ski file ... exiting");
      free(tpm_seal);
      return 1;
    }
    free(tpm_seal);
  }
  else
  {
    pelz_log(LOG_DEBUG, "Write file to .nkl: %s, %d", outpath, sgx_seal_len);
    if (write_bytes_to_file((char *) outpath, sgx_seal, sgx_seal_len))
    {
      pelz_log(LOG_ERR, "error writing data to .nkl file ... exiting");
      free(sgx_seal);
      return 1;
    }
    free(sgx_seal);
  }
  pelz_log(LOG_DEBUG, "File sealed and written to outpath.");
  return 0;
}

int seal_nkl_for_testing(uint8_t * data, size_t data_len, uint8_t ** data_out, size_t *data_out_len)
{
  int ret;

  pelz_log(LOG_DEBUG, "Seal_nkl function");
  pelz_log(LOG_DEBUG, "%s", ENCLAVE_PATH);
  ret = sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
  if (ret != 0)
  {
    pelz_log(LOG_ERR, "sgx_create_enclave error code %x", ret);
    return 1;
  }
  pelz_log(LOG_DEBUG, "sgx_create_enclave return code %x", ret);

  uint16_t key_policy = SGX_KEYPOLICY_MRENCLAVE;
  sgx_attributes_t attribute_mask;

  attribute_mask.flags = 0;
  attribute_mask.xfrm = 0;

  if (kmyth_sgx_seal_nkl(eid, data, data_len, data_out, data_out_len, key_policy, attribute_mask))
  {
    pelz_log(LOG_ERR, "SGX seal failed");
    sgx_destroy_enclave(eid);
    return 1;
  }

  sgx_destroy_enclave(eid);
  return (0);
}

