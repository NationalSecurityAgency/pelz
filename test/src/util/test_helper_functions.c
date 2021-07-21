/*
 * test_helper_functions.c
 */

#include "test_helper_functions.h"

#include <charbuf.h>
#include <unistd.h>
#include <string.h>

charbuf copy_CWD_to_id(char *prefix, char *postfix)
{
  charbuf newBuf;
  char cwd[100];

  getcwd(cwd, sizeof(cwd));
  newBuf = new_charbuf(strlen(prefix) + strlen(cwd) + strlen(postfix));
  memcpy(newBuf.chars, prefix, strlen(prefix));
  memcpy(&newBuf.chars[strlen(prefix)], cwd, strlen(cwd));
  memcpy(&newBuf.chars[strlen(prefix) + strlen(cwd)], postfix, strlen(postfix));
  return (newBuf);
}
