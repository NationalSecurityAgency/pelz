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
#include "pelz_uri_helpers.h"
#include "pelz_key_loaders.h"
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
    return return_value;
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
        break;
      }
      pelz_log(LOG_INFO, "Key load from PELZ URI not implemented.");
      free_charbuf(common_name);
      free_charbuf(key_id);
      break;
    }
  case URI_SCHEME_UNKNOWN:
    // Intentional fallthrough
  default:
    {
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
  {
    pelz_log(LOG_DEBUG, "Error closing pipe");
  }
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
  int len;
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
  {
    pelz_log(LOG_ERR, "Error closing pipe");
  }
  if (ret > 0)
  {
    len = strcspn(buf, "\n");
    *msg = (char *) malloc(len * sizeof(char));
    memcpy(*msg, buf, len);
  }
  return 0;
}

int tokenize_pipe_message(char ***tokens, size_t * num_tokens, char *message, size_t message_length)
{
  //Copy the string because strtok is destructive
  size_t msg_len = message_length;

  if (message[message_length - 1] != '\n')
  {
    msg_len += 1;
  }
  char *msg = (char *) malloc(msg_len * sizeof(char));

  if (!msg)
  {
    pelz_log(LOG_ERR, "Unable to allocate memory.");
    return 1;
  }
  memcpy(msg, message, message_length);
  msg[msg_len - 1] = '\0';

  size_t token_count = 0;
  size_t start = 0;

  // Skip over leading spaces
  while (msg[start] == ' ' && start < (msg_len - 1))
  {
    start++;
  }

  if (start < (msg_len - 1))
  {
    token_count = 1;

    // The -2 is because we know msg[msg_len-1] == 0.
    for (size_t i = start + 1; i < (msg_len - 2); i++)
    {
      if (msg[i] == ' ' && msg[i + 1] != ' ')
      {
        token_count++;
      }
    }
  }
  else
  {
    pelz_log(LOG_ERR, "Unable to tokenize pipe message: %s", msg);
    free(msg);
    return 1;
  }

  *num_tokens = token_count;
  char **ret_tokens = (char **) malloc(token_count * sizeof(char *));

  if (!ret_tokens)
  {
    pelz_log(LOG_ERR, "Unable to allocate memory.");
    free(msg);
    return 1;
  }
  char *save = msg;
  char *token = strtok(msg, " ");

  ret_tokens[0] = (char *) malloc(strlen(token) * sizeof(char) + 1);
  if (!ret_tokens[0])
  {
    pelz_log(LOG_ERR, "Unable to allocate memory.");
    free(save);
    return 1;
  }
  memcpy(ret_tokens[0], token, strlen(token) + 1);  //copy the '\0'
  for (size_t i = 1; i < token_count; i++)
  {
    char *token = strtok(NULL, " ");

    if (token == NULL)
    {
      pelz_log(LOG_ERR, "Unable to tokenize pipe message: %s", msg);
      for (size_t j = 0; j < i; j++)
      {
        free(ret_tokens[j]);
      }
      free(ret_tokens);
      free(save);
      return 1;
    }
    ret_tokens[i] = (char *) malloc(strlen(token) * sizeof(char) + 1);
    if (!ret_tokens[i])
    {
      pelz_log(LOG_ERR, "Unable to allocate memory.");
      for (size_t j = 0; j < i; j++)
      {
        free(ret_tokens[j]);
      }
      free(ret_tokens);
      free(save);
      return 1;
    }
    memcpy(ret_tokens[i], token, strlen(token) + 1);  //copy the '\0'
  }
  if (strtok(NULL, " ") != NULL)
  {
    pelz_log(LOG_ERR, "Unable to tokenize pipe message: %s", msg);
    for (size_t i = 0; i < token_count; i++)
    {
      free(ret_tokens[i]);
    }
    free(ret_tokens);
    free(save);
    return 1;
  }
  free(save);
  *tokens = ret_tokens;
  return 0;
}

ParseResponseStatus parse_pipe_message(char **tokens, size_t num_tokens)
{
  int ret;
  char *path_ext = NULL;
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

  pelz_log(LOG_DEBUG, "Token num: %d", num_tokens);
  if (num_tokens < 2)
  {
    return INVALID;
  }

/*
 *  -1    exit              Terminate running pelz-service
 *  -2    load cert         Loads a server certificate
 *  -3    load private      Loads a private key for connections to key servers
 *  -4    remove cert       Removes a server certificate    
 *  -5    remove all certs  Removes all server certificates
 *  -6    remove key        Removes a key with a specified id
 *  -7    remove all keys   Removes all keys
 */
  switch (atoi(tokens[1]))
  {
  case 1:
    if (unlink(PELZSERVICEIN) == 0)
    {
      pelz_log(LOG_INFO, "Pipe deleted successfully");
    }
    else
    {
      pelz_log(LOG_INFO, "Failed to delete the pipe");
    }
    return EXIT;
  case 2:
    if (num_tokens != 3)
    {
      return INVALID;
    }
    path_ext = strrchr(tokens[2], '.');
    pelz_log(LOG_DEBUG, "Path_ext: %s", path_ext);
    if (strlen(path_ext) == 4)  //4 is the set length of .nkl and .ski
    {
      if (memcmp(path_ext, ".ski", 4) == 0) //4 is the set length of .nkl and .ski
      {
        if (read_bytes_from_file(tokens[2], &data, &data_length))
        {
          pelz_log(LOG_ERR, "Unable to read file %s ... exiting", tokens[2]);
          return UNABLE_RD_F;
        }
        pelz_log(LOG_DEBUG, "Read %d bytes from file %s", data_length, tokens[2]);
        if (tpm2_kmyth_unseal(data, data_length, &nkl_data, &nkl_data_len, (uint8_t *) authString, auth_string_len,
            (uint8_t *) ownerAuthPasswd, oa_passwd_len))
        {
          pelz_log(LOG_ERR, "TPM unseal failed");
          free(data);
          return TPM_UNSEAL_FAIL;
        }

        free(data);
        if (kmyth_sgx_unseal_nkl(eid, nkl_data, nkl_data_len, &handle))
        {
          pelz_log(LOG_ERR, "Unable to unseal contents ... exiting");
          free(nkl_data);
          return SGX_UNSEAL_FAIL;
        }

        free(nkl_data);
        pelz_log(LOG_INFO, "Load cert call not finished");
        return LOAD_CERT_NOT_FIN;
      }
      else if (memcmp(path_ext, ".nkl", 4) == 0)  //4 is the set length of .nkl and .ski
      {
        if (read_bytes_from_file(tokens[2], &data, &data_length))
        {
          pelz_log(LOG_ERR, "Unable to read file %s ... exiting", tokens[2]);
          return UNABLE_RD_F;
        }
        pelz_log(LOG_DEBUG, "Read %d bytes from file %s", data_length, tokens[2]);

        if (kmyth_sgx_unseal_nkl(eid, data, data_length, &handle))
        {
          pelz_log(LOG_ERR, "Unable to unseal contents ... exiting");
          free(data);
          return SGX_UNSEAL_FAIL;
        }

        free(data);
        pelz_log(LOG_INFO, "Load cert call not finished");
        return LOAD_CERT_NOT_FIN;
      }
    }

    pelz_log(LOG_INFO, "Invaild extention for load cert call");
    pelz_log(LOG_DEBUG, "Path_ext: %s", path_ext);
    return INVALID_EXT_CERT;
  case 3:
    if (num_tokens != 3)
    {
      return INVALID;
    }
    path_ext = strrchr(tokens[2], '.');
    pelz_log(LOG_DEBUG, "Path_ext: %s", path_ext);
    if (strlen(path_ext) == 4)  //4 is the set length of .nkl and .ski
    {
      if (memcmp(path_ext, ".ski", 4) == 0) //4 is the set length of .nkl and .ski
      {
        if (read_bytes_from_file(tokens[2], &data, &data_length))
        {
          pelz_log(LOG_ERR, "Unable to read file %s ... exiting", tokens[2]);
          return UNABLE_RD_F;
        }
        pelz_log(LOG_DEBUG, "Read %d bytes from file %s", data_length, tokens[2]);

        if (tpm2_kmyth_unseal(data, data_length, &nkl_data, &nkl_data_len, (uint8_t *) authString, auth_string_len,
            (uint8_t *) ownerAuthPasswd, oa_passwd_len))
        {
          pelz_log(LOG_ERR, "TPM unseal failed");
          free(data);
          return TPM_UNSEAL_FAIL;
        }

        free(data);
        if (kmyth_sgx_unseal_nkl(eid, nkl_data, nkl_data_len, &handle))
        {
          pelz_log(LOG_ERR, "Unable to unseal contents ... exiting");
          free(nkl_data);
          return SGX_UNSEAL_FAIL;
        }

        free(nkl_data);
        pelz_log(LOG_INFO, "Load private call not finished");
        return LOAD_PRIV_NOT_FIN;
      }
      else if (memcmp(path_ext, ".nkl", 4) == 0)  //4 is the set length of .nkl and .ski
      {
        if (read_bytes_from_file(tokens[2], &data, &data_length))
        {
          pelz_log(LOG_ERR, "Unable to read file %s ... exiting", tokens[2]);
          return UNABLE_RD_F;
        }
        pelz_log(LOG_DEBUG, "Read %d bytes from file %s", data_length, tokens[2]);
        if (kmyth_sgx_unseal_nkl(eid, data, data_length, &handle))
        {
          pelz_log(LOG_ERR, "Unable to unseal contents ... exiting");
          free(data);
          return SGX_UNSEAL_FAIL;
        }

        free(data);
        pelz_log(LOG_INFO, "Load private call not finished");
        return LOAD_PRIV_NOT_FIN;
      }
    }

    pelz_log(LOG_INFO, "Invaild extention for load private call");
    pelz_log(LOG_DEBUG, "Path_ext: %s", path_ext);
    return INVALID_EXT_PRIV;
  case 4:
    pelz_log(LOG_INFO, "Remove cert call not added");
    return RM_CERT_NOT_FIN;
  case 5:
    pelz_log(LOG_INFO, "Remove all certs call not added");
    return RM_ALL_CERT_NOT_FIN;
  case 6:
    if (num_tokens != 3)
    {
      return INVALID;
    }
    key_id = new_charbuf(strlen(tokens[2]));  //the number 8 is used because it the number of chars in "pelz -6 "
    memcpy(key_id.chars, tokens[2], key_id.len);
    key_table_delete(eid, &ret, key_id);
    if (ret)
    {
      pelz_log(LOG_ERR, "Delete Key ID from Key Table Failure: %.*s", (int) key_id.len, key_id.chars);
      free_charbuf(&key_id);
      return RM_KEK_FAIL;
    }
    else
    {
      pelz_log(LOG_INFO, "Delete Key ID form Key Table: %.*s", (int) key_id.len, key_id.chars);
      free_charbuf(&key_id);
      return RM_KEK;
    }
  case 7:
    key_table_destroy(eid, &ret);
    if (ret)
    {
      pelz_log(LOG_ERR, "Key Table Destroy Failure");
      return KEK_TAB_DEST_FAIL;
    }
    pelz_log(LOG_INFO, "Key Table Destroyed");

    key_table_init(eid, &ret);
    if (ret)
    {
      pelz_log(LOG_ERR, "Key Table Init Failure");
      return KEK_TAB_INIT_FAIL;
    }
    pelz_log(LOG_INFO, "Key Table Re-Initialized");
    return RM_KEK_ALL;
  default:
    pelz_log(LOG_ERR, "Pipe command invalid: %s %s", tokens[0], tokens[1]);
    return INVALID;
  }
  return INVALID;
}
