#ifndef _TEST_SEAL_H_
#define _TEST_SEAL_H_

/**
 * @brief Reads a file then will call seal_ski and/or seal_nkl to seal the
 * data.  The sealed data will be written to a new file with the extension type
 * ski or nkl based on the final seal function called.
 *
 * @param[in]   filename     The filename in a null-terminated string
 * @param[in]   outpath      The filename for the written output of the sealed data
 * @param[in]   outpath_size The outpath character size
 * @param[in]   tpm          The boolen to determine if to use seal_ski
 * @param[out]  outpath      The determined default filename for the written output sealed data
 *
 * @returns 0 on success, 1 on error
 */
  int seal_for_testing(char *filename, char **outpath, size_t outpath_size, bool tpm);

/**
 * @brief Takes data and calls the kmyth SGX seal function which provides back the SGX sealed data.
 *
 * @param[in]   data          The data to be SGX enclave sealed 
 * @param[in]   data_len      The data character length
 * @param[out]  data_out      The SGX sealed data 
 * @param[out]  data_out_len  The sealed data character length
 *
 * @returns 0 on success, 1 on error
 */
  int seal_nkl_for_testing(uint8_t * data, size_t data_len, uint8_t ** data_out, size_t * data_out_len);

#endif

