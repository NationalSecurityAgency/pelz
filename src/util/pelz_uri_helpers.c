#include <uriparser/Uri.h>

#include "pelz_log.h"
#include "pelz_uri_helpers.h"

URI_SCHEME get_uri_scheme(UriUriA uri)
{
  if (strncmp(uri.scheme.first, "file:", 5) == 0)
  {
    return FILE_URI;
  }
  return URI_SCHEME_UNKNOWN;
}

char *get_filename_from_key_id(char *null_terminated_key_id)
{
  if (null_terminated_key_id == NULL)
  {
    return NULL;
  }

  // The magic 4 here is from the uriparser documentation.
  char *filename = (char *) malloc(strlen((const char *) null_terminated_key_id) - 4);

  if (filename == NULL)
  {
    return NULL;
  }
  if (uriUriStringToUnixFilenameA((const char *) null_terminated_key_id, filename))
  {
    pelz_log(LOG_ERR, "Failed to parse key file name from URI %s\n", null_terminated_key_id);
    free(filename);
    return NULL;
  }
  return filename;
}
