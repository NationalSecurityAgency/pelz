#ifndef INCLUDE_KEY_LOAD_H_
#define INCLUDE_KEY_LOAD_H_

#include "charbuf.h"
#include "pelz_request_handler.h"

typedef enum
{ NO_EXT, NKL, SKI } ExtensionType;

#ifdef __cplusplus
extern "C"
{
#endif
/**
 * <pre>
 * This function returns an ExtensionType to tell program if filename has a .nkl or .ski extension
 * </pre>
 *
 * @param[in] filename Contains the file name string
 *
 * @return ExtensionType
 */
  ExtensionType get_file_ext(char *filename);

/**
 * <pre>
 * Load key from location stated by Key ID
 * <pre>
 *
 * @param[in] key_id.len     the length of the key identifier
 * @param[in] key_id.chars   the key identifier
 *
 * @return 0 on success, 1 on error
 */
  int key_load(charbuf key_id);

/**
 * <pre>
 * Using key_id to check if there is actual file
 * <pre>
 *
 * @param[in] key_id The Identifier for the Key which is also file path and name
 *
 * @return 0 on success, 1 on error
 */
  int file_check(char *file_path);

#ifdef __cplusplus
}
#endif

#endif
