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

  newBuf.len = 0;
  newBuf.chars = NULL;
  if (len > 0)
  {
    newBuf.chars = (unsigned char *) malloc(len);
    if (newBuf.chars != NULL)
    {
      newBuf.len = len;
    }
  }
  return newBuf;
}

void free_charbuf(charbuf * buf)
{
  if (buf != NULL)
  {
    free(buf->chars);
    buf->chars = NULL;
    buf->len = 0;
  }
}

int cmp_charbuf(charbuf buf1, charbuf buf2)
{
  if (buf1.chars == NULL || buf1.len == 0 || buf2.chars == NULL || buf2.len == 0)
  {
    return -3;
  }
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
  if (buf != NULL)
  {
    secure_memset(buf->chars, 0, buf->len);
    free_charbuf(buf);
  }
}

int get_index_for_char(charbuf buf, char c, unsigned int index, int direction)
{
  if (buf.chars == NULL || buf.len == 0)
  {
    return -1;
  }
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

  if ((index < 0) || ((size_t) index < buf.len))
  {
    newBuf = new_charbuf((buf.len - index));
    if (newBuf.chars == NULL || newBuf.len == 0)
    {
      return newBuf;
    }
    memcpy(newBuf.chars, &buf.chars[index], newBuf.len);
    return newBuf;
  }
  return new_charbuf(0);
}
