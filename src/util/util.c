/**
 * util.c
 */

#include "util.h"

void *secure_memset(void *v, int c, size_t n)
{
  volatile unsigned char *p = (volatile unsigned char *) v;

  while (n--)
  {
    *p++ = c;
  }
  return v;
}
