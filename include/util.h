/*
 * util.h
 */

#ifndef INCLUDE_UTIL_H_
#define INCLUDE_UTIL_H_

#include <stdlib.h>
#include <pthread.h>
#include <pelz_request_handler.h>

/**
 * <pre>
 * Clears the contents of a pointer, without running into issues of gcc optimizing around memset.
 * Implementation obtained from:
 *    open-std WG 15 Document: N1381
 *    http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1381.pdf
 * <pre>
 *
 * @param[in] v The pointer containing contents to clear
 * @param[in] c The value to fill the array with
 * @param[in] n The size of the array
 *
 * @return the cleared pointer
 */
void *secure_memset(void *v, int c, size_t n);

#endif /* INCLUDE_UTIL_H_ */
