#ifndef _CMD_INTERFACE_PELZ_H_
#define _CMD_INTERFACE_PELZ_H_

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
  //int pelz_load_file_to_enclave(char *filename, uint64_t * handle);

int parse_interface_cmd();
#endif

