#include <stdlib.h>
#include <stdio.h>

#include "util.h"
#include "pelz_log.h"
#include "pelz_key_loaders.h"
#include "pelz_request_handler.h"

int pelz_load_key_from_file(char *filename, size_t * key_len, unsigned char **key)
{
  if (key_len == NULL || key == NULL)
  {
    pelz_log(LOG_ERR, "No valid pointer provided for key_len or key.");
    return 1;
  }

  if (filename == NULL)
  {
    pelz_log(LOG_ERR, "No filename provided.");
    return 1;
  }

  unsigned char tmp_key[MAX_KEY_LEN + 1];
  FILE *key_file_handle = NULL;

  key_file_handle = fopen(filename, "r");
  if (key_file_handle == NULL)
  {
    pelz_log(LOG_ERR, "Failed to open key file %s", filename);
    return 1;
  }

  *key_len = fread(tmp_key, sizeof(char), MAX_KEY_LEN, key_file_handle);

  // If we've read either max key len or not reached the end
  // of the key file it's likely something went wrong.
  if ((*key_len == MAX_KEY_LEN) || !feof(key_file_handle))
  {
    pelz_log(LOG_ERR, "Error: Failed to fully read key file.");
    secure_memset(tmp_key, 0, *key_len);
    fclose(key_file_handle);
    return 1;
  }
  fclose(key_file_handle);

  *key = (unsigned char *) malloc(*key_len);
  memcpy(*key, tmp_key, *key_len);
  secure_memset(tmp_key, 0, *key_len);
  return 0;
}
