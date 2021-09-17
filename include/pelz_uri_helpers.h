#ifndef _PELZ_URI_HELPERS_H_
#define _PELZ_URI_HELPERS_H_

#include <uriparser/Uri.h>

typedef enum
{
  URI_SCHEME_UNKNOWN,
  FILE_URI,
} URI_SCHEME;

#ifdef __cplusplus
extern "C"
{
#endif

  URI_SCHEME get_uri_scheme(UriUriA uri);
#ifdef __cplusplus
}
#endif

#endif
