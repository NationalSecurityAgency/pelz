#include <stdlib.h>
#include <stdio.h>

#include "util.h"
#include "pelz_log.h"
#include "pelz_loaders.h"
#include "pelz_request_handler.h"

int pelz_load_key_from_file(char *filename, charbuf * key)
{
  size_t key_len;

  if (filename == NULL)
  {
    pelz_log(LOG_ERR, "No filename provided.");
    return 1;
  }

  unsigned char tmp_key[MAX_KEY_LEN];
  FILE *key_file_handle = NULL;

  key_file_handle = fopen(filename, "r");
  if (key_file_handle == NULL)
  {
    pelz_log(LOG_ERR, "Failed to open key file %s", filename);
    return 1;
  }

  key_len = fread(tmp_key, sizeof(char), MAX_KEY_LEN, key_file_handle);

  // If we've not reached EOF something has probably gone wrong.
  if ((key_len == 0) || (!feof(key_file_handle)))
  {
    pelz_log(LOG_ERR, "Error: Failed to fully read key file.");
    secure_memset(tmp_key, 0, key_len);
    fclose(key_file_handle);
    return 1;
  }
  fclose(key_file_handle);

  *key = new_charbuf(key_len);
  if (key->len == 0)
  {
    pelz_log(LOG_ERR, "Error: Failed to allocate memory for key.");
    return 1;
  }
  memcpy(key->chars, tmp_key, key->len);
  secure_memset(tmp_key, 0, key_len);
  return 0;
}

LoaderResponseStatus pelz_load_file_to_enclave(uint8_t path, uint8_t * handle)
{
  ExtentionType ext;
  uint8_t *data = NULL;
  size_t data_len = 0;
  uint8_t *data_out = NULL;
  size_t data_out_len = 0;

  if (read_bytes_from_file(path, &data, &data_len))
  {
    pelz_log(LOG_ERR, "Unable to read file %s ... exiting", path);
    return UNABLE_RD_F;
  }
  pelz_log(LOG_DEBUG, "Read %d bytes from file %s", data_len, path);

  ext = get_file_ext(path);
  switch (ext)
  {
  case SKI:
    pelz_unseal_ski(data, data_len, &data_out, &data_out_len);
    free(data);
    pelz_unseal_nkl(data_out, data_out_len, &handle);
    free(data_out);
    break;
  case NKL:
    pelz_unseal_nkl(data, data_len, &handle);
    free(data);
    break;
  default:
    return INVALID_EXT;
  }
  return OK;
}

LoaderResponseStatus pelz_unseal_ski(uint8_t * data, size_t data_len, uint8_t ** data_out, size_t * data_out_len)
{
  char *authString = NULL;
  size_t auth_string_len = 0;
  const char *ownerAuthPasswd = "";
  size_t oa_passwd_len = 0;

  if (tpm2_kmyth_unseal(data, data_length, &data_out, &data_out_len, (uint8_t *) authString, auth_string_len,
      (uint8_t *) ownerAuthPasswd, oa_passwd_len))
  {
    pelz_log(LOG_ERR, "TPM unseal failed");
    return TPM_UNSEAL_FAIL;
  }

  return OK;
}

LoaderResponseStatus pelz_unseal_nkl(uint8_t * data, size_t data_len, uint8_t ** handle)
{
  if (kmyth_sgx_unseal_nkl(eid, data, data_len, &handle))
  {
    pelz_log(LOG_ERR, "Unable to unseal contents ... exiting");
    return SGX_UNSEAL_FAIL;
  }
  pelz_log(LOG_DEBUG, "SGX unsealed nkl file with %lu handle", handle);
  return OK;
}
