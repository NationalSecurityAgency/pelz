#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <uriparser/Uri.h>
#include <fcntl.h>
#include <stdint.h>
#include <kmyth/kmyth.h>
#include <kmyth/file_io.h>

#include "charbuf.h"
#include "pelz_log.h"
#include "pelz_io.h"
#include "key_table.h"
#include "pelz_request_handler.h"
#include "util.h"

#include "sgx_urts.h"
#include "kmyth_enclave.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"

#define PELZSERVICEIN "/tmp/pelzServiceIn"
#define BUFSIZE 1024

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
  UriUriA key_id_data;
  unsigned char tmp_key[MAX_KEY_LEN + 1];
  FILE *key_key_f = 0;

  const char *error_pos = NULL;

  char *key_uri_to_parse = NULL;

  // URI parser expects a null-terminated string to parse,
  // so we embed the key_id in a 1-longer array and
  // ensure it is null terminated.
  key_uri_to_parse = (char *) calloc(key_id_len + 1, 1);
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

  if (strncmp(key_id_data.scheme.first, "file:", 5) == 0)
  {
    char *filename = NULL;

    // The magic 4 here is derived from the uriparser documentation. It says 
    // the length of the filename returned by uriUriStringToUnixFilenameA
    // will be 5 bytes less than the length of the length of the input
    // uri string including its null terminator. Since key_id_len doesn't include
    // space for a null terminator that means we offset by 4.
    filename = (char *) malloc(key_id_len - 4);
    if (uriUriStringToUnixFilenameA((const char *) key_uri_to_parse, filename))
    {
      pelz_log(LOG_ERR, "Failed to parce key file name");
      uriFreeUriMembersA(&key_id_data);
      free(filename);
      free(key_uri_to_parse);
      return (1);
    }
    free(key_uri_to_parse);
    key_key_f = fopen(filename, "r");

    if (key_key_f == NULL)
    {
      pelz_log(LOG_ERR, "Failed to read key file %s", filename);
      uriFreeUriMembersA(&key_id_data);
      free(filename);
      return (1);
    }
    free(filename);

    *key_len = fread(tmp_key, sizeof(char), MAX_KEY_LEN, key_key_f);
    // If we've read MAX_KEY_LEN but not reached EOF there's probably
    // been a problem.
    if ((*key_len == MAX_KEY_LEN) && !feof(key_key_f))
    {
      pelz_log(LOG_ERR, "Error: Failed to fully read key file");
      secure_memset(tmp_key, 0, *key_len);
      uriFreeUriMembersA(&key_id_data);
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
    pelz_log(LOG_ERR, "Scheme not supported");
    uriFreeUriMembersA(&key_id_data);
    free(key_uri_to_parse);
    return (1);
  }

  uriFreeUriMembersA(&key_id_data);
  return (0);
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

int write_to_pipe(char *pipe, char *msg)
{
  int fd;
  int ret;

  if (file_check(pipe))
  {
    pelz_log(LOG_DEBUG, "Pipe not found");
    return 1;
  }

  fd = open(pipe, O_WRONLY | O_NONBLOCK);
  if (fd == -1)
  {
    pelz_log(LOG_INFO, "Error opening pipe");
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
  return 0;
}

int read_from_pipe(char *pipe, char **msg)
{
  int fd;
  int ret;
  char buf[BUFSIZE];

  if (file_check(pipe))
  {
    pelz_log(LOG_DEBUG, "Pipe not found");
    pelz_log(LOG_INFO, "Unable to read from pipe.");
    return 1;
  }

  fd = open(pipe, O_RDONLY);
  if (fd == -1)
  {
    pelz_log(LOG_ERR, "Error opening pipe");
    return 1;
  }

  ret = read(fd, buf, sizeof(buf));
  if (ret < 0)
  {
    pelz_log(LOG_ERR, "Pipe read failed");
  }

  if (close(fd) == -1)
    pelz_log(LOG_ERR, "Error closing pipe");
  if (ret > 0)
  {
    *msg = (char *) calloc(strlen(buf), sizeof(char));
    memcpy(*msg, buf, strlen(buf));
  }
  return 0;
}

int parse_pipe_message(char *msg, char **response)
{
  int ret;
  int len = 0;
  char opt;
  char *path = NULL;
  char *path_ext;
  charbuf key_id;
  uint8_t *nkl_data = NULL;
  size_t nkl_data_len = 0;
  char *authString = NULL;
  size_t auth_string_len = 0;
  const char *ownerAuthPasswd = "";
  size_t oa_passwd_len = 0;
  uint8_t *data = NULL;
  size_t data_length = 0;
  uint64_t handle;

/*
 *  -1    exit              Terminate running pelz-service
 *  -2    load cert         Loads a server certificate
 *  -3    load private      Loads a private key for connections to key servers
 *  -4    remove cert       Removes a server certificate    
 *  -5    remove all certs  Removes all server certificates
 *  -6    remove key        Removes a key with a specified id
 *  -7    remove all keys   Removes all keys
 */
  if (memcmp(msg, "pelz -", 6) == 0)
  {
    opt = msg[6];
    pelz_log(LOG_DEBUG, "Pipe message: %d, %c, %s", strlen(msg), opt, msg);
    switch (opt)
    {
    case '1':
      if (unlink(PELZSERVICEIN) == 0)
        pelz_log(LOG_INFO, "Pipe deleted successfully");
      else
        pelz_log(LOG_INFO, "Failed to delete the pipe");
      *response = (char *) calloc(18, sizeof(char));
      memcpy(*response, "Exit pelz-service", 17);
      return 1;
    case '2':
      len = strcspn(msg, "\n");
      path = (char *) calloc((len - 7), sizeof(char));  //the number 7 is used because it the number of chars in "pelz -2 " minus 1 for the null terminator
      memcpy(path, &msg[8], len - 8); //the number 8 is used because it the number of chars in "pelz -2 "
      pelz_log(LOG_DEBUG, "File Path: %s", path);
      path_ext = strrchr(path, '.');
      pelz_log(LOG_DEBUG, "Path_ext: %s", path_ext);
      if (strlen(path_ext) == 4)  //4 is the set length of .nkl and .ski
      {
        if (memcmp(path_ext, ".ski", 4) == 0) //4 is the set length of .nkl and .ski
        {
          if (read_bytes_from_file(path, &data, &data_length))
          {
            pelz_log(LOG_ERR, "Unable to read file %s ... exiting", path);
            free(path);
            *response = (char *) calloc(20, sizeof(char));
            memcpy(*response, "Unable to read file", 19);
            return 0;
          }
          pelz_log(LOG_DEBUG, "Read %d bytes from file %s", data_length, path);
          if (tpm2_kmyth_unseal(data, data_length, &nkl_data, &nkl_data_len, (uint8_t *) authString, auth_string_len,
              (uint8_t *) ownerAuthPasswd, oa_passwd_len))
          {
            pelz_log(LOG_ERR, "TPM unseal failed");
            free(data);
            free(path);
            *response = (char *) calloc(18, sizeof(char));
            memcpy(*response, "TPM unseal failed", 17);
            return 0;
          }

          free(data);
          if (kmyth_sgx_unseal_nkl(eid, nkl_data, nkl_data_len, &handle))
          {
            pelz_log(LOG_ERR, "Unable to unseal contents ... exiting");
            free(nkl_data);
            free(path);
            *response = (char *) calloc(18, sizeof(char));
            memcpy(*response, "SGX unseal failed", 17);
            return 0;
          }

          free(nkl_data);
          free(path);
          pelz_log(LOG_INFO, "Load cert call not finished");
          *response = (char *) calloc(28, sizeof(char));
          memcpy(*response, "Load cert call not finished", 27);
          return 0;
        }
        else if (memcmp(path_ext, ".nkl", 4) == 0)  //4 is the set length of .nkl and .ski
        {
          if (read_bytes_from_file(path, &data, &data_length))
          {
            pelz_log(LOG_ERR, "Unable to read file %s ... exiting", path);
            free(path);
            *response = (char *) calloc(20, sizeof(char));
            memcpy(*response, "Unable to read file", 19);
            return 0;
          }
          pelz_log(LOG_DEBUG, "Read %d bytes from file %s", data_length, path);

          if (kmyth_sgx_unseal_nkl(eid, data, data_length, &handle))
          {
            pelz_log(LOG_ERR, "Unable to unseal contents ... exiting");
            free(data);
            free(path);
            *response = (char *) calloc(18, sizeof(char));
            memcpy(*response, "SGX unseal failed", 17);
            return 0;
          }

          free(data);
          free(path);
          pelz_log(LOG_INFO, "Load cert call not finished");
          *response = (char *) calloc(28, sizeof(char));
          memcpy(*response, "Load cert call not finished", 27);
          return 0;
        }
      }

      pelz_log(LOG_INFO, "Invaild extention for load cert call");
      pelz_log(LOG_DEBUG, "Path_ext: %s", path_ext);
      free(path);
      *response = (char *) calloc(36, sizeof(char));
      memcpy(*response, "Invaild extention for load cert call", 36);
      return 0;
    case '3':
      len = strcspn(msg, "\n");
      path = (char *) calloc((len - 7), sizeof(char));  //the number 7 is used because it the number of chars in "pelz -3 " - 1
      memcpy(path, &msg[8], len - 8); //the number 8 is used because it the number of chars in "pelz -3 "
      pelz_log(LOG_DEBUG, "File Path: %s", path);
      path_ext = strrchr(path, '.');
      pelz_log(LOG_DEBUG, "Path_ext: %s", path_ext);
      if (strlen(path_ext) == 4)  //4 is the set length of .nkl and .ski
      {
        if (memcmp(path_ext, ".ski", 4) == 0) //4 is the set length of .nkl and .ski
        {
          if (read_bytes_from_file(path, &data, &data_length))
          {
            pelz_log(LOG_ERR, "Unable to read file %s ... exiting", path);
            free(path);
            *response = (char *) calloc(20, sizeof(char));
            memcpy(*response, "Unable to read file", 19);
            return 0;
          }
          pelz_log(LOG_DEBUG, "Read %d bytes from file %s", data_length, path);

          if (tpm2_kmyth_unseal(data, data_length, &nkl_data, &nkl_data_len, (uint8_t *) authString, auth_string_len,
              (uint8_t *) ownerAuthPasswd, oa_passwd_len))
          {
            pelz_log(LOG_ERR, "TPM unseal failed");
            free(data);
            free(path);
            *response = (char *) calloc(18, sizeof(char));
            memcpy(*response, "TPM unseal failed", 17);
            return 0;
          }

          free(data);
          if (kmyth_sgx_unseal_nkl(eid, nkl_data, nkl_data_len, &handle))
          {
            pelz_log(LOG_ERR, "Unable to unseal contents ... exiting");
            free(nkl_data);
            free(path);
            *response = (char *) calloc(18, sizeof(char));
            memcpy(*response, "SGX unseal failed", 17);
            return 0;
          }

          free(nkl_data);
          free(path);
          pelz_log(LOG_INFO, "Load private call not finished");
          *response = (char *) calloc(31, sizeof(char));
          memcpy(*response, "Load private call not finished", 30);
          return 0;
        }
        else if (memcmp(path_ext, ".nkl", 4) == 0)  //4 is the set length of .nkl and .ski
        {
          if (read_bytes_from_file(path, &data, &data_length))
          {
            pelz_log(LOG_ERR, "Unable to read file %s ... exiting", path);
            free(path);
            *response = (char *) calloc(20, sizeof(char));
            memcpy(*response, "Unable to read file", 19);
            return 0;
          }
          pelz_log(LOG_DEBUG, "Read %d bytes from file %s", data_length, path);
          if (kmyth_sgx_unseal_nkl(eid, data, data_length, &handle))
          {
            pelz_log(LOG_ERR, "Unable to unseal contents ... exiting");
            free(data);
            free(path);
            *response = (char *) calloc(18, sizeof(char));
            memcpy(*response, "SGX unseal failed", 17);
            return 0;
          }

          free(data);
          free(path);
          pelz_log(LOG_INFO, "Load private call not finished");
          *response = (char *) calloc(31, sizeof(char));
          memcpy(*response, "Load private call not finished", 30);
          return 0;
        }
      }

      pelz_log(LOG_INFO, "Invaild extention for load private call");
      pelz_log(LOG_DEBUG, "Path_ext: %s", path_ext);
      free(path);
      *response = (char *) calloc(40, sizeof(char));
      memcpy(*response, "Invaild extention for load private call", 39);
      return 0;
    case '4':
      len = strcspn(msg, "\n");
      path = (char *) calloc((len - 7), sizeof(char));  //the number 7 is used because it the number of chars in "pelz -4 " - 1
      memcpy(path, &msg[8], len - 8); //the number 8 is used because it the number of chars in "pelz -4 "
      free(path);
      pelz_log(LOG_INFO, "Remove cert call not added");
      *response = (char *) calloc(27, sizeof(char));
      memcpy(*response, "Remove cert call not added", 26);
      return 0;
    case '5':
      pelz_log(LOG_INFO, "Remove all certs call not added");
      *response = (char *) calloc(32, sizeof(char));
      memcpy(*response, "Remove all certs call not added", 31);
      return 0;
    case '6':
      len = strcspn(msg, "\n");
      key_id = new_charbuf(len - 8);  //the number 8 is used because it the number of chars in "pelz -6 "
      memcpy(key_id.chars, &msg[8], (key_id.len));
      key_table_delete(eid, &ret, key_id);
      if (ret)
      {
        pelz_log(LOG_ERR, "Delete Key ID from Key Table Failure: %.*s", (int) key_id.len, key_id.chars);
        *response = (char *) calloc(22, sizeof(char));
        memcpy(*response, "Failure to remove key", 21);
      }
      else
      {
        pelz_log(LOG_INFO, "Delete Key ID form Key Table: %.*s", (int) key_id.len, key_id.chars);
        *response = (char *) calloc(12, sizeof(char));
        memcpy(*response, "Removed key", 11);
      }
      free_charbuf(&key_id);
      return 0;
    case '7':
      key_table_destroy(eid, &ret);
      if (ret)
      {
        pelz_log(LOG_ERR, "Key Table Destroy Failure");
        *response = (char *) calloc(26, sizeof(char));
        memcpy(*response, "Key Table Destroy Failure", 25);
        return 1;
      }
      pelz_log(LOG_INFO, "Key Table Destroyed");

      key_table_init(eid, &ret);
      if (ret)
      {
        pelz_log(LOG_ERR, "Key Table Init Failure");
        *response = (char *) calloc(23, sizeof(char));
        memcpy(*response, "Key Table Init Failure", 22);
        return 1;
      }
      pelz_log(LOG_INFO, "Key Table Re-Initialized");

      *response = (char *) calloc(17, sizeof(char));
      memcpy(*response, "All keys removed", 16);
      return 0;
    default:
      pelz_log(LOG_ERR, "Pipe command invalid: %s", msg);
      *response = (char *) calloc(21, sizeof(char));
      memcpy(*response, "Pipe command invalid", 20);
      return 0;
    }
  }
  else
  {
    if (strnlen(msg, 10) == 10)
      pelz_log(LOG_ERR, "Pipe command invalid: %.*s", 10, msg);
    else
      pelz_log(LOG_ERR, "Pipe command invalid: %s", msg);
    *response = (char *) calloc(21, sizeof(char));
    memcpy(*response, "Pipe command invalid", 20);
  }
  return 0;
}
