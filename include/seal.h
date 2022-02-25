#ifndef _SEAL_H_
#define _SEAL_H_

/**
 * @brief Reads a file then will call seal_ski and/or seal_nkl to seal the
 * data.  The sealed data will be written to a new file with the extention type
 * ski or nkl based on the seal function called.
 *
 * @param[in]   filename     The filename in a null-terminated string
 * @param[in]   outpath      The filename for the written output sealed data
 * @param[in]   outpath_size The outpath charater size
 * @param[in]   tpm          The boolen to determine to use seal_ski
 * @param[out]  outpath      The determined default filename for the written output sealed data
 *
 * @returns 0 on success, 1 on error
 */
  int seal(char *filename, char **outpath, size_t outpath_size, bool tpm);

/**
 * @brief Takes data and calls the kmyth TPM seal function providing back TPM sealed data.
 *
 * @param[in]   data          The data to be TPM sealed
 * @param[in]   data_len      The data length
 * @param[out]  data_out      The TPM sealed data
 * @param[out]  data_out_len  The sealed data length
 *
 * @returns 0 on success, 1 on error
 */
  int seal_ski(uint8_t * data, size_t data_len, uint8_t ** data_out, size_t * data_out_len);

/**
 * @brief Takes data and call the kmyth SGX seal function providing back SGX sealed data.
 *
 * @param[in]   data          The data to be SGX enclave sealed 
 * @param[in]   data_len      The data length
 * @param[out]  data_out      The SGX sealed data 
 * @param[out]  data_out_len  The sealed data length
 *
 * @returns 0 on success, 1 on error
 */
  int seal_nkl(uint8_t * data, size_t data_len, uint8_t ** data_out, size_t * data_out_len);

/**
 * @brief Validates the input file path and the data read from file.
 *
 * @param[in]   filename      The input file path
 * @param[out]  data          The data read from the input file
 * @param[out]  data_len      The data length
 *
 * @returns 0 on success, 1 on error
 */
  int read_validate(char *filename, uint8_t ** data, size_t *data_len);

/**
 * @brief Takes an output path and validates or creates a path to write the sealed data.
 *
 * @param[in]   filename      The input path of the sealed data
 * @param[in]   outpath       The specified path for writing the output 
 * @param[in]   outpath_size  The lenght size of the output path charaters
 * @param[in]   tpm           The boolen to determine to use ski extention
 * @param[out]  outpath       The determined default specified path for writing the output
 *
 * @returns 0 on success, 1 on error
 */
  int outpath_validate(char *filename, char **outpath, size_t outpath_size, bool tpm);

/**
 * @brief With no output path specified, determines the output path based on the input path.
 *
 * @param[in]   filename The input path of the sealed data
 * @param[in]   tpm      The boolen to determine to use ski extention
 * @param[out]  outpath  The determined default specified path for writing the output
 *
 * @returns 0 on success, 1 on error
 */
  int outpath_create(char *filename, char **outpath, bool tpm);        
#endif

