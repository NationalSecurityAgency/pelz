/*
 * file_seal_encrypt_decrypt.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include <sys/stat.h>
#include <kmyth/kmyth.h>
#include <kmyth/file_io.h>

#include "pelz_log.h"
#include "file_seal_encrypt_decrypt.h"

#include "pelz_enclave.h"
#include "sgx_seal_unseal_impl.h"
#include "pelz_request_handler.h"

#define ENCLAVE_PATH "sgx/pelz_enclave.signed.so"

int seal(char *filename, char **outpath, size_t outpath_size, bool tpm)
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
  if (seal_nkl(data, data_len, &sgx_seal, &sgx_seal_len))
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
    if (write_bytes_to_file(*outpath, sgx_seal, sgx_seal_len))
    {
      pelz_log(LOG_ERR, "error writing data to .nkl file ... exiting");
      free(sgx_seal);
      return 1;
    }
    free(sgx_seal);
  }
  return 0;
}

//Encrypt key for file is hard coded
int file_encrypt(char *filename, char **outpath, size_t outpath_size)
{
  uint8_t *data = NULL;
  size_t data_len = 0;

  pelz_log(LOG_DEBUG, "File Encryption function");
  //Validating filename and data from file
  if (read_validate(filename, &data, &data_len))
  {
    return 1;
  }

  charbuf plain_data = new_charbuf(data_len);
  memcpy(plain_data.chars, data, plain_data.len);
  free(data);

  charbuf cipher_name = new_charbuf(21);
  memcpy(cipher_name.chars, "AES/GCM/NoPadding/256", cipher_name.len);

  charbuf cipher_data;
  charbuf key;
  charbuf iv;
  charbuf tag;
  RequestResponseStatus status;


  sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
  file_encrypt_in_enclave(eid, &status, plain_data, cipher_name, &cipher_data, &key, &iv, &tag);
  if (status != REQUEST_OK)
  {
    free_charbuf(&plain_data);
    sgx_destroy_enclave(eid);
    return 1;
  }
  free_charbuf(&plain_data);
  sgx_destroy_enclave(eid);


  //Checking and/or setting output path
  if (outpath_validate(filename, outpath, outpath_size, false))
  {
    free_charbuf(&cipher_data);
    free_charbuf(&iv);
    free_charbuf(&tag);
    return 1;
  }

  //Write bytes to file based on outpath
  if (write_bytes_to_file(*outpath, cipher_data.chars, cipher_data.len))
  {
    pelz_log(LOG_ERR, "error writing data to output file ... exiting");
    free_charbuf(&cipher_data);
    free_charbuf(&key);
    free_charbuf(&iv);
    free_charbuf(&tag);
    return 1;
  }
  free_charbuf(&cipher_data);

  //Write bytes to file for KEY
  if (write_bytes_to_file("KEY", key.chars, key.len))
  {
    pelz_log(LOG_ERR, "error writing data to output file ... exiting");
    free_charbuf(&key);
    free_charbuf(&iv);
    free_charbuf(&tag);
    return 1;
  }
  free_charbuf(&key);

  //Write bytes to file for IV
  if (write_bytes_to_file("KEY_IV", iv.chars, iv.len))
  {
    pelz_log(LOG_ERR, "error writing data to output file ... exiting");
    free_charbuf(&iv);
    free_charbuf(&tag);
    return 1;
  }
  free_charbuf(&iv);

  //Write bytes to file for Tag
  if (write_bytes_to_file("KEY_TAG", tag.chars, tag.len))
  {
    pelz_log(LOG_ERR, "error writing data to output file ... exiting");
    free_charbuf(&tag);
    return 1;
  }
  free_charbuf(&tag);
  return 0;
}

//Decrypt key for file is hard coded
int file_decrypt(char *filename, char **outpath, size_t outpath_size)
{
  uint8_t *data = NULL;
  size_t data_len = 0;
  
  pelz_log(LOG_DEBUG, "File decryption function");
  //Validating filename and data from file
  if (read_validate(filename, &data, &data_len))
  { 
    return 1;
  }

  charbuf cipher_data = new_charbuf(data_len);
  memcpy(cipher_data.chars, data, cipher_data.len);
  free(data);
  data_len = 0;

  charbuf cipher_name = new_charbuf(21);
  memcpy(cipher_name.chars, "AES/GCM/NoPadding/256", cipher_name.len);

  if (read_validate("KEY", &data, &data_len))
  {
    return 1;
  }
  charbuf key = new_charbuf(data_len);
  memcpy(key.chars, data, key.len);
  free(data);
  data_len = 0;

  if (read_validate("KEY_IV", &data, &data_len))
  {
    return 1;
  }
  charbuf iv = new_charbuf(data_len);
  memcpy(iv.chars, data, iv.len);
  free(data);
  data_len = 0;
 
  if (read_validate("KEY_TAG", &data, &data_len))
  {
    return 1;
  }
  charbuf tag = new_charbuf(data_len);
  memcpy(tag.chars, data, tag.len);
  free(data);
  data_len = 0;

  charbuf plain_data;
  RequestResponseStatus status;
  
  sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
  file_decrypt_in_enclave(eid, &status, cipher_name, cipher_data, key, iv, tag, &plain_data);
  if (status != REQUEST_OK)
  {
    free_charbuf(&cipher_name);
    free_charbuf(&cipher_data);
    free_charbuf(&key);
    free_charbuf(&iv);
    free_charbuf(&tag);
    sgx_destroy_enclave(eid);
    return 1;
  }
  free_charbuf(&cipher_name);
  free_charbuf(&cipher_data);
  free_charbuf(&key);
  free_charbuf(&iv);
  free_charbuf(&tag);
  sgx_destroy_enclave(eid);

  //Checking and/or setting output path
  if (outpath_validate(filename, outpath, outpath_size, false))
  {
    free_charbuf(&plain_data);
    return 1;
  }
  
  //Write bytes to file based on outpath
  if (write_bytes_to_file(*outpath, plain_data.chars, plain_data.len))
  { 
    pelz_log(LOG_ERR, "error writing data to output file ... exiting");
    free_charbuf(&plain_data);
    return 1;
  }
  free_charbuf(&plain_data);
  return 0;
}

int seal_ski(uint8_t * data, size_t data_len, uint8_t ** data_out, size_t * data_out_len)
{
  pelz_log(LOG_DEBUG, "Seal_ski function");
  if (tpm2_kmyth_seal(data, data_len, data_out, data_out_len, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, false))
  {
    pelz_log(LOG_ERR, "Kmyth TPM seal failed");
    return 1;
  }
  return (0);
}

int seal_nkl(uint8_t * data, size_t data_len, uint8_t ** data_out, size_t *data_out_len)
{
  pelz_log(LOG_DEBUG, "Seal_nkl function");        
  sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);

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

int read_validate(char *filename, uint8_t ** data, size_t *data_len)
{
  pelz_log(LOG_DEBUG, "Read_validate function");       
  // Verify input path exists with read permissions
  if (verifyInputFilePath(filename))
  {
     pelz_log(LOG_ERR, "input path (%s) is not valid ... exiting", filename);
     return 1;
  }

  if (read_bytes_from_file(filename, data, data_len))
  {
     pelz_log(LOG_ERR, "seal input data file read error ... exiting");
     return 1;
  }
  pelz_log(LOG_DEBUG, "read in %d bytes of data to be wrapped", data_len);

  // validate non-empty plaintext buffer specified
  if (data_len == 0 || data == NULL)
  {
     pelz_log(LOG_ERR, "no input data ... exiting");
     free(data);
     return 1;
  }
  return 0;
}

int outpath_validate(char *filename, char **outpath, size_t outpath_size, bool tpm)
{
  pelz_log(LOG_DEBUG, "Outpath_validate function");        
  if ((*outpath != NULL) && (outpath_size != 0))
  {        
    return 0;
  }
  else
  {
    if(outpath_create(filename, outpath, tpm))
    {
      return 1;
    }
  }
  return 0;
}

int outpath_create(char *filename, char **outpath, bool tpm)
{
  const char *ext;
  const char *TPM_EXT = ".ski";
  const char *NKL_EXT = ".nkl";

  pelz_log(LOG_DEBUG, "Outpath_create function");
  if (tpm)
  {
    ext = TPM_EXT;
  }
  else
  {
    ext = NKL_EXT;
  }

  // If output file not specified, set output path to basename(filename) with
  // a extension in the directory that the application is being run from.
  char *original_fn = basename(filename);

  *outpath = (char *) malloc((strlen(original_fn) + strlen(ext) + 1) * sizeof(char));

  // Make sure resultant default file name does not have empty basename
  if (*outpath == NULL)
  {
    pelz_log(LOG_ERR, "invalid default filename derived ... exiting");
    free(*outpath);
    return 1;
  }

  sprintf(*outpath, "%.*s%.*s", (int) strlen(original_fn), original_fn, (int) strlen(ext), ext);
  // Make sure default filename we constructed doesn't already exist
  struct stat st = { 0 };
  if (!stat(*outpath, &st))
  {
    pelz_log(LOG_ERR, "default output filename (%s) already exists ... exiting", *outpath);
    free(*outpath);
    return 1;
  }

  pelz_log(LOG_DEBUG, "output file not specified, default = %s", *outpath);
  return 0;
}
