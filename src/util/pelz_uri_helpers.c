#include <uriparser/Uri.h>
#include <stddef.h>

#include "charbuf.h"
#include "pelz_uri_helpers.h"
#include "pelz_log.h"

URI_SCHEME get_uri_scheme(UriUriA uri)
{
  if (strncmp(uri.scheme.first, "file:", 5) == 0)
  {
    return FILE_URI;
  }
  if (strncmp(uri.scheme.first, "pelz:", 5) == 0)
  {
    return PELZ_URI;
  }
  return URI_SCHEME_UNKNOWN;
}

char *get_filename_from_key_id(const char *null_terminated_key_id)
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

int get_pelz_uri_parts(UriUriA uri, charbuf * common_name, int *port, charbuf * key_id, charbuf * additional_data)
{
  ptrdiff_t field_length;

  // Extract the hostname
  field_length = uri.hostText.afterLast - uri.hostText.first;
  *common_name = new_charbuf((size_t) field_length);
  memcpy(common_name->chars, uri.hostText.first, field_length);

  // Extract the port
  field_length = uri.pathHead->text.afterLast - uri.pathHead->text.first;
  char *port_text = (char *) calloc((1 + field_length), sizeof(char));

  memcpy(port_text, uri.pathHead->text.first, field_length);
  *port = strtol(port_text, NULL, 10);
  free(port_text);

  // Extract the key UID
  field_length = uri.pathHead->next->text.afterLast - uri.pathHead->next->text.first;
  *key_id = new_charbuf((size_t) field_length);
  memcpy(key_id->chars, uri.pathHead->next->text.first, field_length);

  // Extract any additional data
  if (additional_data != NULL)
  {
    field_length = uri.pathTail->text.afterLast - uri.pathHead->next->next->text.first;
    *additional_data = new_charbuf((size_t) field_length);
    memcpy(additional_data->chars, uri.pathHead->next->next->text.first, field_length);
  }
  return 0;

}
