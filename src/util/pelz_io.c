#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <uriparser/Uri.h>
#include <fcntl.h>

#include "charbuf.h"
#include "pelz_log.h"
#include "pelz_io.h"
#include "key_table.h"
#include "pelz_request_handler.h"
#include "pelz_uri_helpers.h"
#include "pelz_key_loaders.h"
#include "util.h"

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"

#define PELZFIFO "/tmp/pelzfifo"

void ocall_malloc(size_t size, char **buf)
{
  *buf = (char *) malloc(size);
}

void ocall_free(void *ptr, size_t len)
{
  secure_memset(ptr, 0, len);
  free(ptr);
}

int get_file_ext(charbuf buf, int *ext)
{
  int period_index = 0;
  unsigned int ext_len = 0;
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
  int return_value = 1;
  UriUriA key_id_data;

  const char *error_pos = NULL;
  char *key_uri_to_parse = NULL;

  // URI parser expects a null-terminated string to parse,
  // so we embed the key_id in a 1-longer array and
  // ensure it is null terminated.
  key_uri_to_parse = (char *) calloc(key_id_len + 1, 1);
  if (key_uri_to_parse == NULL)
  {
    return 1;
  }
  memcpy(key_uri_to_parse, key_id, key_id_len);

  pelz_log(LOG_DEBUG, "Starting Key Load");
  pelz_log(LOG_DEBUG, "Key ID: %.*s", key_id_len, key_id);
  if (uriParseSingleUriA(&key_id_data, (const char *) key_uri_to_parse, &error_pos) != URI_SUCCESS
    || key_id_data.scheme.first == NULL || key_id_data.scheme.afterLast == NULL || error_pos != NULL)
  {
    pelz_log(LOG_ERR, "Key ID URI Parse Error");
    free(key_uri_to_parse);
    return (1);
  }

  URI_SCHEME scheme = get_uri_scheme(key_id_data);

  switch (scheme)
  {
  case FILE_URI:
    {
      char *filename = get_filename_from_key_id(key_uri_to_parse);

      if (filename == NULL)
      {
        pelz_log(LOG_ERR, "Failed to parse filename from URI %s\n", key_uri_to_parse);
        break;
      }

      if (pelz_load_key_from_file(filename, key_len, key))
      {
        pelz_log(LOG_ERR, "Failed to read key file %s", filename);
        free(filename);
        break;
      }
      free(filename);
      return_value = 0;
      break;
    }
  case PELZ_URI:
    {
      charbuf *common_name = NULL;
      int port;
      charbuf *key_id = NULL;

      if (get_pelz_uri_parts(key_id_data, common_name, &port, key_id, NULL) != 0)
      {
        pelz_log(LOG_ERR, "Failed to extract data from pelz uri");
        if (common_name != NULL)
        {
          free_charbuf(common_name);
        }
        if (key_id != NULL)
        {
          free_charbuf(key_id);
        }
        break;
      }

      free_charbuf(common_name);
      free_charbuf(key_id);
      break;
    }
  case URI_SCHEME_UNKNOWN:
    // Intentional fallthrough
  default:
    {                           //pelz://common_name/port/key_uuid/<anything else KMIP will need>

      pelz_log(LOG_ERR, "Scheme not supported");
    }
  }
  free(key_uri_to_parse);
  uriFreeUriMembersA(&key_id_data);
  return return_value;
}

int file_check(char *file_path)
{
  pelz_log(LOG_DEBUG, "File Check Key ID: %s", file_path);
  if (file_path == NULL)
  {
    pelz_log(LOG_DEBUG, "No file path provided.");
    return (1);
  }
  else if (access(file_path, F_OK) == -1)
  {
    pelz_log(LOG_DEBUG, "File cannot be found.");
    return (1);
  }
  else if (access(file_path, R_OK) == -1)
  {
    pelz_log(LOG_DEBUG, "File cannot be read.");
    return (1);
  }
  return (0);
}

int write_to_pipe(char *msg)
{
  int fd;
  int ret;

  if (file_check((char *) PELZFIFO))
  {
    pelz_log(LOG_DEBUG, "Pipe not found");
    printf("Unable to connect to the pelz-service. Please make sure service is running.\n");
    return 1;
  }

  fd = open(PELZFIFO, O_WRONLY | O_NONBLOCK);
  if (fd == -1)
  {
    if (unlink(PELZFIFO) == 0)
      pelz_log(LOG_INFO, "Pipe deleted successfully");
    else
      pelz_log(LOG_INFO, "Failed to delete the pipe");
    printf("Unable to connect to the pelz-service. Please make sure service is running.\n");
    return 1;
  }
  ret = write(fd, msg, strlen(msg) + 1);
  if (close(fd) == -1)
    pelz_log(LOG_DEBUG, "Error closing pipe");
  if (ret == -1)
  {
    pelz_log(LOG_DEBUG, "Error writing to pipe");
    return 1;
  }
  printf("Pelz command options sent to pelz-service\n");
  return 0;
}

int read_pipe(char *msg)
{
  int ret;
  int len;
  char opt;
  charbuf key_id;
  charbuf path;

/*
 *  -e    exit     Terminate running pelz-service
 *  -l    load     Loads a value of type <type> (currently either cert or private)
 *  -c    cert     Server certificate
 *  -p    private  Private key for connections to key servers
 *  -r    remove   Removes a value of type <target> (currently either cert or key)
 *  -k    key      Key with a specified id
 *  -a    all      Indicate all key or cert
 */

  if (memcmp(msg, "pelz -", 6) == 0)
  {
    opt = msg[6];
    pelz_log(LOG_DEBUG, "Pipe message: %d, %c, %s", strlen(msg), opt, msg);
    switch (opt)
    {
    case 'e':
      if (unlink(PELZFIFO) == 0)
        pelz_log(LOG_INFO, "Pipe deleted successfully");
      else
        pelz_log(LOG_INFO, "Failed to delete the pipe");
      return 1;
    case 'l':
      if (memcmp(&msg[8], "-", 1) == 0)
        opt = msg[9];
      else
      {
        pelz_log(LOG_ERR, "Pipe command invalid: %s", msg);
        return 0;
      }
      switch (opt)
      {
      case 'c':
        len = strcspn(msg, "\n");
        path = new_charbuf(len - 11); //the number 11 is used because it the number of chars in "pelz -l -c "
        memcpy(path.chars, &msg[11], (path.len));
        free_charbuf(&path);
        pelz_log(LOG_INFO, "Load cert call not added");
        return 0;
      case 'p':
        len = strcspn(msg, "\n");
        path = new_charbuf(len - 11); //the number 11 is used because it the number of chars in "pelz -l -p "
        memcpy(path.chars, &msg[11], (path.len));
        free_charbuf(&path);
        pelz_log(LOG_INFO, "Load private call not added");
        return 0;
      default:
        pelz_log(LOG_ERR, "Pipe command invalid: %s", msg);
        return 0;
      }
    case 'r':
      if (memcmp(&msg[8], "-", 1) == 0)
        opt = msg[9];
      else
      {
        pelz_log(LOG_ERR, "Pipe command invalid: %s", msg);
        return 0;
      }
      switch (opt)
      {
      case 'k':
        if (memcmp(&msg[10], " -a", 3) == 0)
        {
          key_table_destroy(eid, &ret);
          if (ret)
          {
            pelz_log(LOG_ERR, "Key Table Destroy Failure");
            return 1;
          }
          pelz_log(LOG_INFO, "Key Table Destroyed");
          key_table_init(eid, &ret);
          if (ret)
          {
            pelz_log(LOG_ERR, "Key Table Init Failure");
            return 1;
          }
          pelz_log(LOG_INFO, "Key Table Re-Initialized");
          return 0;
        }
        else
        {
          len = strcspn(msg, "\n");
          key_id = new_charbuf(len - 11); //the number 11 is used because it the number of chars in "pelz -r -k "
          memcpy(key_id.chars, &msg[11], (key_id.len));
          key_table_delete(eid, &ret, key_id);
          if (ret)
            pelz_log(LOG_ERR, "Delete Key ID from Key Table Failure: %.*s", (int) key_id.len, key_id.chars);
          else
            pelz_log(LOG_INFO, "Delete Key ID form Key Table: %.*s", (int) key_id.len, key_id.chars);
          free_charbuf(&key_id);
          return 0;
        }
      case 'c':
        if (memcmp(&msg[10], " -a", 3) == 0)
        {
          pelz_log(LOG_INFO, "Remove all certs call not added");
          return 0;
        }
        else
        {
          len = strcspn(msg, "\n");
          path = new_charbuf(len - 11); //the number 11 is used because it the number of chars in "pelz -r -c "
          memcpy(path.chars, &msg[11], (path.len));
          free_charbuf(&path);
          pelz_log(LOG_INFO, "Remove cert call not added");
          return 0;
        }
      default:
        pelz_log(LOG_ERR, "Pipe command invalid: %s", msg);
        return 0;
      }
    default:
      pelz_log(LOG_ERR, "Pipe command invalid: %s", msg);
      return 0;
    }
  }
  else
  {
    if (strnlen(msg, 10) == 10)
      pelz_log(LOG_ERR, "Pipe command invalid: %.*s", 10, msg);
    else
      pelz_log(LOG_ERR, "Pipe command invalid: %s", msg);
  }
  return 0;
}
