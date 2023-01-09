#ifndef _PELZ_URI_HELPERS_H_
#define _PELZ_URI_HELPERS_H_

#include <uriparser/Uri.h>

#include "charbuf.h"

typedef enum
{
  URI_SCHEME_UNKNOWN,
  FILE_URI,
  PELZ_URI,
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
 * @param[in] The (already parsed) URI.
 *
 * @return The filename, or NULL on error.
 */
  char *get_filename_from_key_id(UriUriA uri);

/**
 * @brief Extracts the necessary parts from a parsed pelz uri.
 * 
 * @param[in] uri   The (already parsed) URI
 *
 * @param[in,out] common_name Pointer to charbuf to hold the common name
 *
 * @return 0 on success, 1 on error
 */
  int get_pelz_uri_hostname(UriUriA uri, charbuf * common_name);

/**
 * @brief Extracts the necessary parts from a parsed pelz uri.
 * 
 * @param[in] uri The (already parsed) URI
 *
 * @param[in,out] port Pointer to int to hold the port
 *
 * @return 0 on success, 1 on error
 */
  int get_pelz_uri_port(UriUriA uri, charbuf * port);

/**
 * @brief Extracts the necessary parts from a parsed pelz uri.
 * 
 * @param[in] uri The (already parsed) URI
 *
 * @param[in,out] key_id Pointer to charbuf to hold the key_id
 *
 * @return 0 on success, 1 on error
 */
  int get_pelz_uri_key_UID(UriUriA uri, charbuf * key_id);

/**
 * @brief Extracts the necessary parts from a parsed pelz uri.
 * 
 * @param[in] uri   The (already parsed) URI
 *
 * @param[in,out] additional_data Pointer to charbuf to hold additional data
 *                                May be NULL.
 *
 * @return 0 on success, 1 on error
 */
  int get_pelz_uri_additional_data(UriUriA uri, charbuf * additional_data);

#ifdef __cplusplus
}
#endif

#endif
