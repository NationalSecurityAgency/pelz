#ifndef _FILE_ENC_DEC_H_
#define _FILE_ENC_DEC_H_

/**
 * @brief Reads a file then will encrypt the file with hard coded key. The encrypted
 * file data will be written to a new file.
 *
 * @param[in]     filename     The filename in a null-terminated string
 * @param[in/out] outpath      The filename for the written output of the sealed data.
 *                             If specified by the user as an input, that value is used.
 *                             Otherwise, it is set to a default filename.
 * @param[in]     outpath_size The outpath character size
 *
 * @returns 0 on success, 1 on error
 */
  int file_encrypt(char *filename, char **outpath, size_t outpath_size);

/**
 * @brief Reads a file then will decrypt the file with hard coded key. The decrypted
 * file data will be written to a new file.
 *
 * @param[in]     filename     The filename in a null-terminated string
 * @param[in/out] outpath      The filename for the written output of the sealed data.
 *                             If specified by the user as an input, that value is used.
 *                             Otherwise, it is set to a default filename.
 * @param[in]     outpath_size The outpath character size
 *
 * @returns 0 on success, 1 on error
 */
  int file_decrypt(char *filename, char **outpath, size_t outpath_size);

/**
 * @brief Validates the input file path and the data read from file.
 *
 * @param[in]   filename      The input file path
 * @param[out]  data          The data read from the input file
 * @param[out]  data_len      The data character length
 *
 * @returns 0 on success, 1 on error
 */
  int read_validate(char *filename, uint8_t ** data, size_t *data_len);

/**
 * @brief Takes an output path and validates or creates a path to write the sealed data.
 *
 * @param[in]   filename      The input path of the sealed data
 * @param[in]   outpath       The specified path for writing the output 
 * @param[in]   outpath_size  The character length of the output path
 * @param[out]  outpath       The determined default or provided specified path for writing the output
 *
 * @returns 0 on success, 1 on error
 */
  int outpath_validate(char *filename, char **outpath, size_t outpath_size);

/**
 * @brief With no output path specified, determines the output path based on the input path.
 *
 * @param[in]   filename The input path of the sealed data
 * @param[out]  outpath  The determined default specified path for writing the output
 *
 * @returns 0 on success, 1 on error
 */
  int outpath_create(char *filename, char **outpath);        
#endif

