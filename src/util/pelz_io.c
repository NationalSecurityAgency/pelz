#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <uriparser/Uri.h>

#include "charbuf.h"
#include "pelz_log.h"
#include "pelz_io.h"
#include "key_table.h"
#include "pelz_request_handler.h"
#include "util.h"

#ifdef PELZ_SGX_UNTRUSTED
void ocall_malloc(size_t size, char **buf)
{
  *buf = (char *) malloc(size);
}

void ocall_free(void *ptr, size_t len)
{
  secure_memset(ptr, 0, len);
  free(ptr);
}
#endif

int get_file_ext(charbuf buf, int *ext)
{
  int period_index = 0;
  int ext_len = 0;
  int ext_type_size = 3;
  const char *ext_type[3] = { ".txt", ".pem", ".key" };

  period_index = get_index_for_char(buf, '.', (buf.len - 1), 1);
  ext_len = (buf.len - period_index);

  // If buf.chars is null terminated we don't want to include
  // the null terminator in the extension, since we're going
  // to use strlen (applied to one of the ext_type entries)
  // to specify a memcmp length, and strlen won't include
  // the null terminator.
  if (buf.chars[buf.len - 1] == '\0')
  {
    ext_len--;
  }
  pelz_log(LOG_DEBUG, "Finding file extension.");
  for (int i = 0; i < ext_type_size; i++)
  {
    if (ext_len == strlen(ext_type[i]))
    {
      if (memcmp(buf.chars + period_index, ext_type[i], strlen(ext_type[i])) == 0)
      {
        *ext = i + 1;
        break;
      }
    }
  }
  return (0);
}

int key_load(size_t key_id_len, unsigned char *key_id, size_t * key_len, unsigned char **key)
{
  UriUriA key_id_data;
  unsigned char tmp_key[MAX_KEY_LEN + 1];
  FILE *key_key_f = 0;

  const char *error_pos = NULL;

  char *key_uri_to_parse = NULL;

  key_uri_to_parse = calloc(key_id_len + 1, 1);
  memcpy(key_uri_to_parse, key_id, key_id_len);

  pelz_log(LOG_DEBUG, "Starting Key Load");
  pelz_log(LOG_DEBUG, "Key ID: %.*s", key_id_len, key_id);
  if (uriParseSingleUriA(&key_id_data, (const char *) key_uri_to_parse, &error_pos) != URI_SUCCESS
    || key_id_data.scheme.first == NULL || key_id_data.scheme.afterLast == NULL)
  {
    free(key_uri_to_parse);
    return (1);
  }

  if (strncmp(key_id_data.scheme.first, "file", 4) == 0)
  {
    char *filename = NULL;

    // Magic 5 is inherited from uriparser
    filename = malloc(key_id_len - 5);
    if (uriUriStringToUnixFilenameA((const char *) key_uri_to_parse, filename))
    {
      free(filename);
      free(key_uri_to_parse);
      return (1);
    }
    free(key_uri_to_parse);

    key_key_f = fopen(filename, "r");

    if (key_key_f == NULL)
    {
      pelz_log(LOG_ERR, "Failed to read key file %s\n", filename);
      free(filename);
      return (1);
    }
    free(filename);

    *key_len = fread(tmp_key, sizeof(char), MAX_KEY_LEN, key_key_f);
    // If we've read MAX_KEY_LEN but not reached EOF there's probably
    // been a problem.
    if ((*key_len == MAX_KEY_LEN) && !feof(key_key_f))
    {
      pelz_log(LOG_ERR, "Error: Failed to fully read key file.");
      fclose(key_key_f);
      return (1);
    }
    *key = (unsigned char *) malloc(*key_len);
    memcpy(*key, tmp_key, *key_len);
    secure_memset(tmp_key, 0, *key_len);
    fclose(key_key_f);
  }
  else
  {
    free(key_uri_to_parse);
    return (1);
  }

  return (0);
}

int key_id_parse(charbuf key_id, URIValues * uri)
{
  charbuf buf;
  int index = 0;
  char *path = NULL;

  pelz_log(LOG_DEBUG, "Starting Key ID Parse");
  if (strncmp((char *) key_id.chars, "file:", 5) == 0)
  {
    pelz_log(LOG_DEBUG, "Key ID File Scheme");
    uri->type = 1;
    buf = new_charbuf(key_id.len - 5);
    memcpy(buf.chars, &key_id.chars[5], buf.len);
    if (buf.chars[1] == '/')
    {
      pelz_log(LOG_DEBUG, "File Scheme Auth-Path");
      index = get_index_for_char(buf, '/', 2, 0);
      if (index == -1)
      {
        pelz_log(LOG_ERR, "Invalid FILE Syntax");
        free_charbuf(&buf);
        return (1);
      }
      uri->f_values.auth = new_charbuf(index);
      memcpy(uri->f_values.auth.chars, buf.chars, uri->f_values.auth.len);
      uri->f_values.path = new_charbuf(buf.len - index);
      memcpy(uri->f_values.path.chars, &buf.chars[index], uri->f_values.path.len);
      index = get_index_for_char(buf, '/', (buf.len - 1), 1);
      if (index == -1)
      {
        pelz_log(LOG_ERR, "Invalid FILE Syntax");
        free_charbuf(&buf);
        free_charbuf(&uri->f_values.auth);
        free_charbuf(&uri->f_values.path);
        return (1);
      }
      uri->f_values.f_name = new_charbuf((buf.len - index - 1));
      memcpy(uri->f_values.f_name.chars, &buf.chars[(index + 1)], uri->f_values.f_name.len);
    }
    else
    {
      pelz_log(LOG_DEBUG, "No File Scheme Auth-Path");
      uri->f_values.auth.chars = NULL;
      uri->f_values.auth.len = 0;
      uri->f_values.path = new_charbuf(buf.len);
      memcpy(uri->f_values.path.chars, buf.chars, buf.len);
      index = get_index_for_char(buf, '/', (buf.len - 1), 1);
      if (index == -1)
      {
        pelz_log(LOG_ERR, "Invalid FILE Syntax");
        free_charbuf(&buf);
        free_charbuf(&uri->f_values.path);
        return (1);
      }
      uri->f_values.f_name = new_charbuf((buf.len - index - 1));
      memcpy(uri->f_values.f_name.chars, &buf.chars[(index + 1)], uri->f_values.f_name.len);
    }
    free_charbuf(&buf);
    path = (char *) calloc((uri->f_values.path.len + 1), sizeof(char));
    memcpy(path, &uri->f_values.path.chars[0], uri->f_values.path.len);
    if (file_check(path))       //Removing the first char from the string is so we can test and needs to be fixed for production.
    {
      pelz_log(LOG_ERR, "File Error");
      free(path);
      if (uri->f_values.auth.len != 0)
      {
        free_charbuf(&uri->f_values.auth);
      }
      free_charbuf(&uri->f_values.path);
      free_charbuf(&uri->f_values.f_name);
      return (1);
    }
    free(path);
    pelz_log(LOG_DEBUG, "File Auth/Path/File: %.*s, %.*s, %.*s", uri->f_values.auth.len, uri->f_values.auth.chars,
      uri->f_values.path.len, uri->f_values.path.chars, uri->f_values.f_name.len, uri->f_values.f_name.chars);
    return (0);
  }

  if (strncmp((char *) key_id.chars, "ftp:", 4) == 0)
  {
    pelz_log(LOG_DEBUG, "Key ID FTP Scheme");
    uri->type = 2;
    buf = new_charbuf(key_id.len - 4);
    memcpy(buf.chars, &key_id.chars[4], buf.len);
    pelz_log(LOG_DEBUG, "Buf: %.*s", buf.len, buf.chars);
    if (buf.chars[1] == '/')
    {
      pelz_log(LOG_DEBUG, "FTP Start Parse");
      index = get_index_for_char(buf, '/', 2, 0);
      if (index != -1)
      {
        pelz_log(LOG_DEBUG, "URL Found");
        uri->ftp_values.url_path = new_charbuf(buf.len - index);
        memcpy(uri->ftp_values.url_path.chars, &buf.chars[index], uri->ftp_values.url_path.len);
        free_charbuf(&buf);
        buf = new_charbuf(index);
        memcpy(buf.chars, &key_id.chars[4], buf.len);
        index = get_index_for_char(buf, ':', (buf.len - 1), 1);
        if (index != -1)
        {
          pelz_log(LOG_DEBUG, "Port valid");
          uri->ftp_values.port = new_charbuf(buf.len - index - 1);
          memcpy(uri->ftp_values.port.chars, &buf.chars[(index + 1)], uri->ftp_values.port.len);
          uri->ftp_values.host = new_charbuf(index);
          memcpy(uri->ftp_values.host.chars, buf.chars, uri->ftp_values.host.len);
          free_charbuf(&buf);
          pelz_log(LOG_DEBUG, "File Host/Port/Path: %.*s, %.*s, %.*s", uri->ftp_values.host.len, uri->ftp_values.host.chars,
            uri->ftp_values.port.len, uri->ftp_values.port.chars, uri->ftp_values.url_path.len, uri->ftp_values.url_path.chars);
          return (0);
        }
        free_charbuf(&uri->ftp_values.url_path);
      }
    }
    if (buf.len != 0)
    {
      free_charbuf(&buf);
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
