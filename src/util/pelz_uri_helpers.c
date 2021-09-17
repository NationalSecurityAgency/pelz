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
