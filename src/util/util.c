/**
 * util.c
 */

#include <util.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <pelz_request_handler.h>
#include <CharBuf.h>
#include <pelz_log.h>

void *secure_memset(void *v, int c, size_t n)
{
  volatile unsigned char *p = v;

  while (n--)
  {
    *p++ = c;
  }
  return v;
}

int get_file_ext(CharBuf buf, int *ext)
{
  int period_index = 0;
  char *ext_value;
  int ext_len = 0;
  int ext_type_size = 3;
  char *ext_type[3] = { ".txt", ".pem", ".key" };

  period_index = getIndexForChar(buf, '.', (buf.len - 1), 1);
  ext_len = (buf.len - period_index);
  ext_value = calloc(ext_len, sizeof(char));
  memcpy(ext_value, &buf.chars[period_index], ext_len);
  pelz_log(LOG_DEBUG, "Finding file extension.");
  for (int i = 0; i < ext_type_size; i++)
  {
    if (ext_len == strlen(ext_type[i]))
    {
      if (strncmp(ext_value, ext_type[i], strlen(ext_type[i])) == 0)
      {
        *ext = i + 1;
        break;
      }
    }
  }
  free(ext_value);
  return (0);
}

int key_load(KeyEntry * key_values)
{
  URIValues key_id_values;
  int file_type = 0;
  unsigned char tmp_key[MAX_KEY_LEN];
  char *path = NULL;
  FILE *key_txt_f = 0;
  FILE *key_key_f = 0;

  key_id_values.type = 0;

  pelz_log(LOG_DEBUG, "Starting Key Load");
  pelz_log(LOG_DEBUG, "Key ID: %s", key_values->key_id.chars);
  if (key_id_parse(key_values->key_id, &key_id_values) != 0)
  {
    return (1);
  }

  pelz_log(LOG_DEBUG, "URIValues Parsed\nKey Retrieval Started: %d", key_id_values.type);
  switch (key_id_values.type)
  {
  case (F_SCHEME):
    get_file_ext(key_id_values.f_values.f_name, &file_type);
    pelz_log(LOG_DEBUG, "File Type: %d", file_type);
    if (key_id_values.f_values.auth.len == 0 || strncmp((char *) key_id_values.f_values.auth.chars, "//localhost", 11) == 0 ||
      strncmp((char *) key_id_values.f_values.auth.chars, "//", 2) == 0)
    {
      switch (file_type)
      {
      case (TXT_EXT):
        path = calloc((key_id_values.f_values.path.len + 1), sizeof(char));
        memcpy(path, &key_id_values.f_values.path.chars[0], key_id_values.f_values.path.len);
        key_txt_f = fopen(path, "r");
        fgets((char *) tmp_key, (MAX_KEY_LEN + 1), key_txt_f);
        fclose(key_txt_f);
        free(path);
        key_values->key = newCharBuf(strlen((char *) tmp_key));
        memcpy(key_values->key.chars, tmp_key, key_values->key.len);
        secure_memset(tmp_key, 0, key_values->key.len);
        if (key_id_values.f_values.auth.len != 0)
        {
          freeCharBuf(&key_id_values.f_values.auth);
        }
        freeCharBuf(&key_id_values.f_values.path);
        freeCharBuf(&key_id_values.f_values.f_name);
        break;
      case (PEM_EXT):
        pelz_log(LOG_INFO, "PEM file retrieve is not setup yet.");
        if (&key_id_values.f_values.auth != 0)
        {
          freeCharBuf(&key_id_values.f_values.auth);
        }
        freeCharBuf(&key_id_values.f_values.path);
        freeCharBuf(&key_id_values.f_values.f_name);
        return (1);
      case (KEY_EXT):
        pelz_log(LOG_DEBUG, "Reading Key File");
        path = calloc(key_id_values.f_values.path.len, sizeof(char));
        memcpy(path, &key_id_values.f_values.path.chars[0], key_id_values.f_values.path.len);
        key_key_f = fopen(path, "r");
        fread(tmp_key, sizeof(char), MAX_KEY_LEN, key_key_f);
        fclose(key_key_f);
        free(path);
        key_values->key = newCharBuf(MAX_KEY_LEN);
        memcpy(key_values->key.chars, tmp_key, key_values->key.len);
        secure_memset(tmp_key, 0, key_values->key.len);
        if (key_id_values.f_values.auth.len != 0)
        {
          freeCharBuf(&key_id_values.f_values.auth);
        }
        freeCharBuf(&key_id_values.f_values.path);
        freeCharBuf(&key_id_values.f_values.f_name);
        break;
      default:
        if (&key_id_values.f_values.auth != 0)
        {
          freeCharBuf(&key_id_values.f_values.auth);
        }
        freeCharBuf(&key_id_values.f_values.path);
        freeCharBuf(&key_id_values.f_values.f_name);
        pelz_log(LOG_ERR, "Error: File Type Undetermined\n");
        return (1);
      }
      break;
    }
    freeCharBuf(&key_id_values.f_values.auth);
    freeCharBuf(&key_id_values.f_values.path);
    freeCharBuf(&key_id_values.f_values.f_name);
    pelz_log(LOG_WARNING, "Non localhost authorities are not valid.\n");
    return (1);
  case (FTP):
    freeCharBuf(&key_id_values.ftp_values.host);
    freeCharBuf(&key_id_values.ftp_values.port);
    freeCharBuf(&key_id_values.ftp_values.url_path);
    pelz_log(LOG_ERR, "Socket file retrieve is not setup yet.");
    return (1);
  default:
    pelz_log(LOG_ERR, "Error: Scheme Type Undetermined.");
    return (1);
  }
  return (0);
}

int key_id_parse(CharBuf key_id, URIValues * uri)
{
  CharBuf buf;
  int index = 0;
  char *path = NULL;

  pelz_log(LOG_DEBUG, "Starting Key ID Parse");
  if (strncmp((char *) key_id.chars, "file:", 5) == 0)
  {
    pelz_log(LOG_DEBUG, "Key ID File Scheme");
    uri->type = 1;
    buf = newCharBuf(key_id.len - 5);
    memcpy(buf.chars, &key_id.chars[5], buf.len);
    if (buf.chars[1] == '/')
    {
      pelz_log(LOG_DEBUG, "File Scheme Auth-Path");
      index = getIndexForChar(buf, '/', 2, 0);
      if (index == -1)
      {
        pelz_log(LOG_ERR, "Invalid FILE Syntax");
        freeCharBuf(&buf);
        return (1);
      }
      uri->f_values.auth = newCharBuf(index);
      memcpy(uri->f_values.auth.chars, buf.chars, uri->f_values.auth.len);
      uri->f_values.path = newCharBuf(buf.len - index);
      memcpy(uri->f_values.path.chars, &buf.chars[index], uri->f_values.path.len);
      index = getIndexForChar(buf, '/', (buf.len - 1), 1);
      if (index == -1)
      {
        pelz_log(LOG_ERR, "Invalid FILE Syntax");
        freeCharBuf(&buf);
        freeCharBuf(&uri->f_values.auth);
        freeCharBuf(&uri->f_values.path);
        return (1);
      }
      uri->f_values.f_name = newCharBuf((buf.len - index - 1));
      memcpy(uri->f_values.f_name.chars, &buf.chars[(index + 1)], uri->f_values.f_name.len);
    }
    else
    {
      pelz_log(LOG_DEBUG, "No File Scheme Auth-Path");
      uri->f_values.auth.chars = NULL;
      uri->f_values.auth.len = 0;
      uri->f_values.path = newCharBuf(buf.len);
      memcpy(uri->f_values.path.chars, buf.chars, buf.len);
      index = getIndexForChar(buf, '/', (buf.len - 1), 1);
      if (index == -1)
      {
        pelz_log(LOG_ERR, "Invalid FILE Syntax");
        freeCharBuf(&buf);
        freeCharBuf(&uri->f_values.path);
        return (1);
      }
      uri->f_values.f_name = newCharBuf((buf.len - index - 1));
      memcpy(uri->f_values.f_name.chars, &buf.chars[(index + 1)], uri->f_values.f_name.len);
    }
    freeCharBuf(&buf);
    path = calloc((uri->f_values.path.len + 1), sizeof(char));
    memcpy(path, &uri->f_values.path.chars[0], uri->f_values.path.len);
    if (file_check(path))       //Removing the first char from the string is so we can test and needs to be fixed for production.
    {
      pelz_log(LOG_ERR, "File Error");
      free(path);
      if (uri->f_values.auth.len != 0)
      {
        freeCharBuf(&uri->f_values.auth);
      }
      freeCharBuf(&uri->f_values.path);
      freeCharBuf(&uri->f_values.f_name);
      return (1);
    }
    free(path);
    pelz_log(LOG_DEBUG, "File Auth/Path/File: %s, %s, %s", uri->f_values.auth.chars, uri->f_values.path.chars,
      uri->f_values.f_name.chars);
    return (0);
  }

  if (strncmp((char *) key_id.chars, "ftp:", 4) == 0)
  {
    pelz_log(LOG_DEBUG, "Key ID FTP Scheme");
    uri->type = 2;
    buf = newCharBuf(key_id.len - 4);
    memcpy(buf.chars, &key_id.chars[4], buf.len);
    pelz_log(LOG_DEBUG, "Buf: %s", buf.chars);
    if (buf.chars[1] == '/')
    {
      pelz_log(LOG_DEBUG, "FTP Start Parse");
      index = getIndexForChar(buf, '/', 2, 0);
      if (index != -1)
      {
        pelz_log(LOG_DEBUG, "URL Found");
        uri->ftp_values.url_path = newCharBuf(buf.len - index);
        memcpy(uri->ftp_values.url_path.chars, &buf.chars[index], uri->ftp_values.url_path.len);
        freeCharBuf(&buf);
        buf = newCharBuf(index);
        memcpy(buf.chars, &key_id.chars[4], buf.len);
        index = getIndexForChar(buf, ':', (buf.len - 1), 1);
        if (index != -1)
        {
          pelz_log(LOG_DEBUG, "Port valid");
          uri->ftp_values.port = newCharBuf(buf.len - index - 1);
          memcpy(uri->ftp_values.port.chars, &buf.chars[(index + 1)], uri->ftp_values.port.len);
          uri->ftp_values.host = newCharBuf(index);
          memcpy(uri->ftp_values.host.chars, buf.chars, uri->ftp_values.host.len);
          freeCharBuf(&buf);
          pelz_log(LOG_DEBUG, "File Host/Port/Path: %s, %s, %s", uri->ftp_values.host.chars, uri->ftp_values.port.chars,
            uri->ftp_values.url_path.chars);
          return (0);
        }
        freeCharBuf(&uri->ftp_values.url_path);
      }
    }
    if (buf.len != 0)
    {
      freeCharBuf(&buf);
    }
    pelz_log(LOG_ERR, "Invalid FTP Syntax");
    return (1);
  }

  //Key ID is invalid because it does not follow the file scheme (RFC 8089) or ftp scheme (RFC 959).
  pelz_log(LOG_ERR, "Key ID is Invalid");
  return (1);
}

int file_check(char *file_path)
{
  pelz_log(LOG_DEBUG, "File Check Key ID: %s", file_path);
  if (file_path == NULL)
  {
    pelz_log(LOG_ERR, "No file path provided.");
    return (1);
  }
  else if (access(file_path, F_OK) == -1)
  {
    pelz_log(LOG_ERR, "File cannot be found.");
    return (1);
  }
  else if (access(file_path, R_OK) == -1)
  {
    pelz_log(LOG_ERR, "File cannot be read.");
    return (1);
  }
  return (0);
}

int encodeBase64Data(unsigned char *raw_data, size_t raw_data_size, unsigned char **base64_data, size_t * base64_data_size)
{
  if (raw_data == NULL || raw_data_size == 0)
  {
    pelz_log(LOG_ERR, "No input data provided for encoding.");
    return (1);
  }

  BIO *bio_mem = NULL;
  BIO *bio64 = NULL;
  BUF_MEM *bioptr = NULL;

  if ((bio64 = BIO_new(BIO_f_base64())) == NULL)
  {
    pelz_log(LOG_ERR, "Failed to create a new BIO for encoding.");
    return (1);
  }

  if ((bio_mem = BIO_new(BIO_s_mem())) == NULL)
  {
    pelz_log(LOG_ERR, "Failed to create a new BIO for encoding.");
    BIO_free_all(bio64);
    return (1);
  }

  bio64 = BIO_push(bio64, bio_mem);
  if (BIO_write(bio64, raw_data, raw_data_size) != raw_data_size)
  {
    pelz_log(LOG_ERR, "Bio_write failed.");
    BIO_free_all(bio64);
    return (1);
  }

  if (BIO_flush(bio64) != 1)
  {
    pelz_log(LOG_ERR, "Bio_flush failed.");
    BIO_free_all(bio64);
    return (1);
  }

  BIO_get_mem_ptr(bio64, &bioptr);
  if (bioptr == NULL)
  {
    pelz_log(LOG_ERR, "No underlying BIO_MEM structure.");
    BIO_free_all(bio64);
    return 1;
  }

  *base64_data_size = bioptr->length;
  *base64_data = (unsigned char *) malloc(*base64_data_size + 1);

  if (*base64_data == NULL)
  {
    pelz_log(LOG_ERR, "Failed to allocate memory for base64 encoding.");
    BIO_free_all(bio64);
    return (1);
  }

  memcpy(*base64_data, bioptr->data, (*base64_data_size) - 1);
  (*base64_data)[(*base64_data_size) - 1] = '\n';
  (*base64_data)[(*base64_data_size)] = '\0';
  BIO_free_all(bio64);
  return (0);
}

int decodeBase64Data(unsigned char *base64_data, size_t base64_data_size, unsigned char **raw_data, size_t * raw_data_size)
{
  if (base64_data == NULL || base64_data_size == 0)
  {
    pelz_log(LOG_ERR, "No data provided to decode.");
    return (1);
  }
  if (base64_data_size > INT_MAX)
  {
    pelz_log(LOG_ERR, "Encoded data length (%lu bytes) exceeds maximum allowable length (%d bytes.)", base64_data_size,
      INT_MAX);
    return (1);
  }

  *raw_data = (unsigned char *) malloc(base64_data_size);
  if (*raw_data == NULL)
  {
    pelz_log(LOG_ERR, "Failed to allocate memory for decode base64 content.");
    return (1);
  }

  BIO *bio64 = NULL;

  if ((bio64 = BIO_new(BIO_f_base64())) == NULL)
  {
    pelz_log(LOG_ERR, "Failed to create a new BIO for decoding.");
    free(*raw_data);
    return (1);
  }

  BIO *bio_mem = NULL;

  if ((bio_mem = BIO_new_mem_buf(base64_data, base64_data_size)) == NULL)
  {
    pelz_log(LOG_ERR, "Create source BIO error.\n");
    BIO_free_all(bio64);
    return 1;
  }

  bio64 = BIO_push(bio64, bio_mem);
  int bytes_read = BIO_read(bio64, *raw_data, base64_data_size);

  if (bytes_read < 0)
  {
    pelz_log(LOG_ERR, "Error reading bytes from BIO chain.\n");
    BIO_free_all(bio64);
    return 1;
  }

  (*raw_data)[bytes_read] = '\0';
  *raw_data_size = bytes_read;
  BIO_free_all(bio64);
  return (0);
}
