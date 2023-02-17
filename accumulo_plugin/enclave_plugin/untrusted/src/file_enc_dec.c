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
  if (outpath_validate(filename, outpath, outpath_size))
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
  if (outpath_validate(filename, outpath, outpath_size))
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

int outpath_validate(char *filename, char **outpath, size_t outpath_size)
{
  pelz_log(LOG_DEBUG, "Outpath_validate function");        
  if ((*outpath != NULL) && (outpath_size != 0))
  {        
    return 0;
  }
  else
  {
    if(outpath_create(filename, outpath))
    {
      return 1;
    }
  }
  return 0;
}

int outpath_create(char *filename, char **outpath)
{
  pelz_log(LOG_DEBUG, "Outpath_create function");
  // If output file not specified, set output path to basename(filename) with
  // a extension in the directory that the application is being run from.
  char *original_fn = basename(filename);

  *outpath = (char *) malloc((strlen(original_fn) + 6) * sizeof(char));

  // Make sure resultant default file name does not have empty basename
  if (*outpath == NULL)
  {
    pelz_log(LOG_ERR, "invalid default filename derived ... exiting");
    free(*outpath);
    return 1;
  }

  sprintf(*outpath, "%.*s.copy", (int) strlen(original_fn), original_fn);
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
