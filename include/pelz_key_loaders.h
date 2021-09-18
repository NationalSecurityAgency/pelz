#ifndef _PELZ_KEY_LOADERS_H_
#define _PELZ_KEY_LOADERS_H_

#ifdef __cplusplus
extern "C"
{
#endif

  int pelz_load_key_from_file(char *filename, size_t * key_len, unsigned char **key);

#ifdef __cplusplus
}
#endif

#endif
