/*
 * CharBuf.c
 */

#include <stdio.h>
#include <unistd.h>

#include "CharBuf.h"
#include "util.h"
#include "pelz_log.h"

CharBuf newCharBuf(size_t len)
{
  CharBuf newBuf;

  newBuf.chars = (unsigned char *) malloc(len);
  newBuf.len = len;
  return (newBuf);
}

void freeCharBuf(CharBuf * buf)
{
  free((*buf).chars);
  (*buf).chars = NULL;
  (*buf).len = 0;
}

int cmpCharBuf(CharBuf buf1, CharBuf buf2)
{
  if (buf1.len == buf2.len)
  {
    int ret = memcmp(buf1.chars, buf2.chars, buf1.len);

    if (ret == 0)
      return (0);
    else if (ret > 0)
      return (1);
    else if (ret < 0)
      return (-1);
  }
  else if (buf1.len < buf2.len)
    return (-2);
  else if (buf1.len > buf2.len)
    return (2);

  return (-3);
}

void secureFreeCharBuf(CharBuf * buf)
{
  secure_memset(buf->chars, 0, buf->len);
  freeCharBuf(buf);
}

int getIndexForChar(CharBuf buf, char c, int index, int direction)
{
  if (0 <= index && index < buf.len)
  {
    if (direction == 0)
    {
      for (int i = index; i < buf.len; i++)
      {
        if (c == buf.chars[i])
          return (i);
      }
    }
    else if (direction == 1)
    {
      for (int i = index; i >= 0; i--)
      {
        if (c == buf.chars[i])
        {
          return (i);
        }
      }
    }
  }
  return (-1);
}

CharBuf copyBytesFromBuf(CharBuf buf, int index)
{
  CharBuf newBuf;

  newBuf = newCharBuf((buf.len - index));
  memcpy(newBuf.chars, &buf.chars[index], newBuf.len);
  return (newBuf);
}

CharBuf copyCWDToId(char *prefix, char *postfix)
{
  CharBuf newBuf;
  char cwd[100];

  getcwd(cwd, sizeof(cwd));
  newBuf = newCharBuf(strlen(prefix) + strlen(cwd) + strlen(postfix));
  memcpy(newBuf.chars, prefix, strlen(prefix));
  memcpy(&newBuf.chars[strlen(prefix)], cwd, strlen(cwd));
  memcpy(&newBuf.chars[strlen(prefix) + strlen(cwd)], postfix, strlen(psotfix));
  retun(newBuf);
}
