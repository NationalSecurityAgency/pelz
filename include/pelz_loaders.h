#ifndef _PELZ_LOADERS_H_
#define _PELZ_LOADERS_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#include "pelz_io.h"
#include "charbuf.h"

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

/**
 * @brief Loads a .nkl or .ski file into the enclave data table. Based on the file
 * type the function will call pelz_unseal_ski and/or pelz_unseal_nkl to unseal the
 * data and load it into the enclave data table at location based on handle value.
 *
 * @param[in]   filename  The filename in a null-terminated string
 * @param[out]  handle    The handle value for the data location in the kmyth unseal data table
 *
 * @returns 0 on success, 1 on error
 */
  int pelz_load_file_to_enclave(char *filename, uint64_t * handle);

/**
 * @brief Takes TPM sealed data and calls the kmyth TPM unseal function to output unsealed data.
 *
 * @param[in]   data          The data to be TPM unsealed from the loaded file
 * @param[in]   data_len      The data length
 * @param[out]  data_out      The TPM unsealed data from the loaded file
 * @param[out]  data_out_len  The unsealed data length
 *
 * @returns 0 on success, 1 on error
 */
  int pelz_unseal_ski(uint8_t * data, size_t data_len, uint8_t ** data_out, size_t * data_out_len);

/**
 * @brief Takes SGX enclave sealed data and call the kmyth SGX unseal function providing back a handle value.
 *
 * @param[in]   data          The data to be SGX enclave unsealed from the loaded file
 * @param[in]   data_len      The data length
 * @param[out]  handle        The handle value for the data location in the kmyth unseal data table
 *
 * @returns 0 on success, 1 on error
 */
  int pelz_unseal_nkl(uint8_t * data, size_t data_len, uint64_t * handle);

#ifdef __cplusplus
};
#endif
#endif
