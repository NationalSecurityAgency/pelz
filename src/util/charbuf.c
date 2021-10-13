/*
 * charbuf.c
 */

#include <stdio.h>
#include <unistd.h>

#include "charbuf.h"
#include "util.h"
#include "pelz_log.h"

charbuf new_charbuf(size_t len)
{
  charbuf newBuf;

  newBuf.chars = (unsigned char *) malloc(len);
  newBuf.len = len;
  return (newBuf);
}

void free_charbuf(charbuf * buf)
{
  free((*buf).chars);
  (*buf).chars = NULL;
  (*buf).len = 0;
}

int cmp_charbuf(charbuf buf1, charbuf buf2)
{
  if (buf1.len == buf2.len)
  {
    int ret = memcmp(buf1.chars, buf2.chars, buf1.len);

    if (ret == 0)
    {
      return (0);
    }
    else if (ret > 0)
    {
      return (1);
    }
    else if (ret < 0)
    {
      return (-1);
    }
  }
  else if (buf1.len < buf2.len)
  {
    return (-2);
  }
  else if (buf1.len > buf2.len)
  {
    return (2);
  }

  return (-3);
}

void secure_free_charbuf(charbuf * buf)
{
  secure_memset(buf->chars, 0, buf->len);
  free_charbuf(buf);
}

int get_index_for_char(charbuf buf, char c, unsigned int index, int direction)
{
  if (0 <= index && index < buf.len)
  {
    if (direction == 0)
    {
      for (unsigned int i = index; i < buf.len; i++)
      {
        if (c == buf.chars[i])
        {
          return (i);
        }
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

charbuf copy_chars_from_charbuf(charbuf buf, int index)
{
  charbuf newBuf;

  newBuf = new_charbuf((buf.len - index));
  memcpy(newBuf.chars, &buf.chars[index], newBuf.len);
  return (newBuf);
}
