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
/**
 * @brief Returns the URI_SCHEME enum for the specified URI.
 *
 * @param[in] uri  The (already parsed) URI
 *
 * @return The URI_SCHEME enum, for URI_SCHEME_UNKNOWN if the
 *         URI does not have a recognized scheme.
 */
URI_SCHEME get_uri_scheme(UriUriA uri);

/**
 * @brief Returns the filename from a null-terminated key_id.
 *
 * @param[in] null_terminated_key_id The key id embedded in a
 *                                   null-terminated string
 *
 * @return The filename, or NULL on error.
 */
char *get_filename_from_key_id(char *null_terminated_key_id);
#ifdef __cplusplus
}
#endif

#endif
