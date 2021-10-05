#ifndef _PELZ_KEY_LOADERS_H_
#define _PELZ_KEY_LOADERS_H_

#ifdef __cplusplus
extern "C"
{
#endif
/**
 * @brief Loads a key from a specified key file.
 *
 * @param[in]     filename  The filename in a null-terminated string
 * @param[in,out] key_len   A pointer to a size_t to hold the key length
 * @param[in,out] key       A pointer to a location to allocate memory for 
 *                          the key.
 *
 * @returns 0 on success, 1 on error
 */
  int pelz_load_key_from_file(char *filename, size_t * key_len, unsigned char **key);

#ifdef __cplusplus
}
#endif

#endif
