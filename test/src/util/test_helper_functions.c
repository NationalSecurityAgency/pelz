/*
 * test_helper_functions.c
 */

#include "test_helper_functions.h"

#include <charbuf.h>
#include <pelz_log.h>
#include <unistd.h>
#include <string.h>

charbuf copy_CWD_to_id(const char *prefix, const char *postfix)
{
  charbuf newBuf;
  char *pointer;
  char cwd[100];

  pointer = getcwd(cwd, sizeof(cwd));
  if (pointer == NULL)
  {
    pelz_log(LOG_ERR, "Get Current Working Directory Failure");
    return (newBuf);
  }
  newBuf = new_charbuf(strlen(prefix) + strlen(cwd) + strlen(postfix));
  memcpy(newBuf.chars, prefix, strlen(prefix));
  memcpy(&newBuf.chars[strlen(prefix)], cwd, strlen(cwd));
  memcpy(&newBuf.chars[strlen(prefix) + strlen(cwd)], postfix, strlen(postfix));
  return (newBuf);
}
