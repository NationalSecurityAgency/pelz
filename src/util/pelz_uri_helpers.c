#include <uriparser/Uri.h>
#include <stddef.h>
#include <limits.h>

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

char *get_filename_from_key_id(UriUriA uri)
{
  if (uri.pathHead == NULL)
  {
    pelz_log(LOG_ERR, "Invalid URI.");
    return NULL;
  }

  ptrdiff_t field_length = uri.pathTail->text.afterLast - uri.pathHead->text.first;

  if (field_length <= 0)
  {
    pelz_log(LOG_ERR, "Invalid URI field length.");
    return NULL;
  }

  // The extra 2 bytes here are to prepend '/' and to append a null byte.
  char *filename = (char *) calloc(field_length + 2, sizeof(char));

  if (filename == NULL)
  {
    pelz_log(LOG_ERR, "Failed to allocate memory for filename.");
    return NULL;
  }
  filename[0] = '/';
  memcpy(filename + 1, uri.pathHead->text.first, field_length);
  return filename;
}

int get_pelz_uri_hostname(UriUriA uri, unsigned char **common_name, size_t *common_name_len)
{
  ptrdiff_t field_length;

  // Extract the hostname
  field_length = uri.hostText.afterLast - uri.hostText.first;
  if (field_length <= 0)
  {
    pelz_log(LOG_ERR, "Invalid URI field length.");
    return 1;
  }

  // The extra 2 bytes here are to prepend '/' and to append a null byte.
  *common_name_len = field_length + 2;
  *common_name = (unsigned char *) calloc(*common_name_len, sizeof(char));

  memcpy(*common_name, uri.hostText.first, field_length);
  return 0;
}

int get_pelz_uri_port(UriUriA uri, int *port)
{
  ptrdiff_t field_length;

  // Extract the port
  field_length = uri.pathHead->text.afterLast - uri.pathHead->text.first;
  if (field_length <= 0)
  {
    pelz_log(LOG_ERR, "Invalid URI field length.");
    return 1;
  }
  char *port_text = (char *) calloc((1 + field_length), sizeof(char));

  if (port_text == NULL)
  {
    pelz_log(LOG_ERR, "Failed to initialize memory.");
    return 1;
  }
  memcpy(port_text, uri.pathHead->text.first, field_length);
  long int port_long = strtol(port_text, NULL, 10);

  free(port_text);
  if (port_long < 0 || port_long > INT_MAX)
  {
    pelz_log(LOG_ERR, "Invalid port specified: %ld", port_long);
    return 1;
  }
  *port = (int) port_long;
  return 0;
}

int get_pelz_uri_key_UID(UriUriA uri, unsigned char **key_id, size_t *key_id_len)
{
  ptrdiff_t field_length;

  // Extract the key UID
  field_length = uri.pathHead->next->text.afterLast - uri.pathHead->next->text.first;
  if (field_length <= 0)
  {
    pelz_log(LOG_ERR, "Invalid URI field length.");
    return 1;
  }

  // The extra 2 bytes here are to prepend '/' and to append a null byte.
  *key_id_len = field_length + 2;
  *key_id = (unsigned char *) calloc(*key_id_len, sizeof(char));

  memcpy(*key_id, uri.pathHead->next->text.first, field_length);
  return 0;
}

int get_pelz_uri_additional_data(UriUriA uri, charbuf * additional_data)
{
  ptrdiff_t field_length;

  // Extract any additional data
  if (additional_data != NULL)
  {
    field_length = uri.pathTail->text.afterLast - uri.pathHead->next->next->text.first;
    if (field_length <= 0)
    {
      pelz_log(LOG_ERR, "Invalid URI field length.");
      return 1;
    }

    *additional_data = new_charbuf((size_t) field_length);
    if (additional_data->chars == NULL)
    {
      pelz_log(LOG_ERR, "Failed to initialize charbuf.");
      return 1;
    }

    memcpy(additional_data->chars, uri.pathHead->next->next->text.first, field_length);
  }
  return 0;
}
