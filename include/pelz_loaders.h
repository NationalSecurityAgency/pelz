#ifndef _PELZ_LOADERS_H_
#define _PELZ_LOADERS_H_

typedef enum
{ OK, INVALID_EXT, UNABLE_RD_F, TPM_UNSEAL_FAIL, SGX_UNSEAL_FAIL } LoaderResponseStatus;

#ifdef __cplusplus
extern "C"
{
#endif
/**
 * @brief Loads a key from a specified key file. Expects the file to consist of
 *        unformatted, raw key bytes. The entire contents of the file are read
 *        and output as the key.
 *
 * @param[in]     filename  The filename in a null-terminated string
 * @param[in,out] key.len   A pointer to a size_t to hold the key length
 * @param[in,out] key.char  A pointer to a location to allocate memory for 
 *                          the key.
 *
 * @returns 0 on success, 1 on error
 */
  int pelz_load_key_from_file(char *filename, charbuf * key);

  LoaderResponseStatus pelz_load_file_to_enclave((uint8_t path, uint8_t * handle);
    LoaderResponseStatus pelz_unseal_ski(uint8_t * data, size_t data_len, uint8_t ** data_out, size_t * data_out_len);
    LoaderResponseStatus pelz_unseal_nkl(uint8_t * data, size_t data_len, uint8_t ** handle);
#ifdef __cplusplus
  }
#endif

#endif
