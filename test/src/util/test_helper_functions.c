/*
 * test_helper_functions.c
 */

#include "CharBuf.h"
#include <unistd.h>
#include <string.h>

CharBuf copyCWDToId(char *prefix, char *postfix)
{
  CharBuf newBuf;
  char cwd[100];

  getcwd(cwd, sizeof(cwd));
  newBuf = newCharBuf(strlen(prefix) + strlen(cwd) + strlen(postfix));
  memcpy(newBuf.chars, prefix, strlen(prefix));
  memcpy(&newBuf.chars[strlen(prefix)], cwd, strlen(cwd));
  memcpy(&newBuf.chars[strlen(prefix) + strlen(cwd)], postfix, strlen(postfix));
  return (newBuf);
}
