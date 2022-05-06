#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>
#include <uriparser/Uri.h>
#include <kmyth/kmyth.h>
#include <kmyth/file_io.h>

#include "charbuf.h"
#include "pelz_log.h"
#include "pelz_io.h"
#include "common_table.h"
#include "pelz_request_handler.h"
#include "pelz_uri_helpers.h"
#include "pelz_loaders.h"
#include "util.h"
#include "fifo_thread.h"

#include "sgx_urts.h"
#include "sgx_seal_unseal_impl.h"
#include "pelz_enclave.h"
#include ENCLAVE_HEADER_UNTRUSTED

#define BUFSIZE 1024

void ocall_malloc(size_t size, unsigned char **buf)
{
  *buf = (unsigned char *) malloc(size);
}

void ocall_free(void *ptr, size_t len)
{
  secure_memset(ptr, 0, len);
  free(ptr);
}

ExtensionType get_file_ext(char *filename)
{
  charbuf buf;
  size_t period_index = 0;
  size_t ext_len = 0;
  size_t ext_type_len = 4;
  const char *ext_type[2] = { ".nkl", ".ski" };

  if (filename == NULL)
  {
    return NO_EXT;
  }

  buf = new_charbuf(strlen(filename));
  memcpy(buf.chars, filename, buf.len);

  // We know that if filename != NULL then buf.len > 0, so there's
  // no wrap-around concern with buf.len-1.
  period_index = get_index_for_char(buf, '.', (buf.len - 1), 1);
  if (period_index == SIZE_MAX)
  {
    free_charbuf(&buf);
    return NO_EXT;
  }

  ext_len = (buf.len - period_index);
  if (ext_len == 0)
  {
    free_charbuf(&buf);
    return NO_EXT;
  }

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
  if (ext_len != ext_type_len)
  {
    free_charbuf(&buf);
    return NO_EXT;
  }
  else if (memcmp(buf.chars + period_index, ext_type[0], ext_type_len) == 0)
  {
    free_charbuf(&buf);
    return NKL;
  }
  else if (memcmp(buf.chars + period_index, ext_type[1], ext_type_len) == 0)
  {
    free_charbuf(&buf);
    return SKI;
  }
  free_charbuf(&buf);
  return NO_EXT;
}

int key_load(charbuf key_id)
{
  charbuf key;
  int return_value = 1;
  TableResponseStatus status;
  UriUriA key_id_data;

  const char *error_pos = NULL;
  char *key_uri_to_parse = NULL;

  // URI parser expects a null-terminated string to parse,
  // so we embed the key_id in a 1-longer array and
  // ensure it is null terminated.
  key_uri_to_parse = (char *) calloc(key_id.len + 1, 1);
  if (key_uri_to_parse == NULL)
  {
    return return_value;
  }
  memcpy(key_uri_to_parse, key_id.chars, key_id.len);

  pelz_log(LOG_DEBUG, "Starting Key Load");
  pelz_log(LOG_DEBUG, "Key ID: %.*s", key_id.len, key_id.chars);
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
      char *filename = get_filename_from_key_id(key_id_data);
      uint64_t handle;

      if (filename == NULL)
      {
        pelz_log(LOG_ERR, "Failed to parse filename from URI %s\n", key_uri_to_parse);
        break;
      }

      if (get_file_ext(filename) == NO_EXT)
      {
        if (pelz_load_key_from_file(filename, &key) != 0)
        {
          pelz_log(LOG_ERR, "Failed to read key file %s", filename);
          break;
        }
        key_table_add_key(eid, &status, key_id, key);
        secure_free_charbuf(&key);
      }
      else
      {
        if (pelz_load_file_to_enclave(filename, &handle) != 0)
        {
          pelz_log(LOG_ERR, "Failed to read key file %s", filename);
          break;
        }
        key_table_add_from_handle(eid, &status, key_id, handle);
      }
      free(filename);
      switch (status)
      {
      case ERR:
        {
          pelz_log(LOG_ERR, "Failed to load key to table");
          return_value = 1;
          break;
        }
      case ERR_MEM:
        {
          pelz_log(LOG_ERR, "Key Table memory allocation greater than specified limit.");
          return_value = 1;
          break;
        }
      case RET_FAIL:
        {
          pelz_log(LOG_ERR, "Failure to retrieve data from unseal table.");
          return_value = 1;
          break;
        }
      case ERR_BUF:
        {
          pelz_log(LOG_ERR, "Charbuf creation error.");
          return_value = 1;
          break;
        }
      case ERR_REALLOC:
        {
          pelz_log(LOG_ERR, "Key List Space Reallocation Error");
          return_value = 1;
          break;
        }
      case OK:
        {
          pelz_log(LOG_DEBUG, "Key added to table.");
          return_value = 0;
          break;
        }
      default:
        {
          return_value = 1;
          break;
        }
      }
      break;
    }
  case PELZ_URI:
    {
      pelz_log(LOG_DEBUG, "Pelz Scheme Start");
      unsigned char *common_name;
      size_t common_name_len = 0;
      unsigned char *server_key_id;
      size_t server_key_id_len = 0;
      int port;

      if (get_pelz_uri_hostname(key_id_data, &common_name, &common_name_len) != 0)
      {
        pelz_log(LOG_ERR, "Failed to extract hostname from pelz uri");
        break;
      }

      if (get_pelz_uri_port(key_id_data, &port) != 0)
      {
        pelz_log(LOG_ERR, "Failed to extract port from pelz uri");
        break;
      }

      if (get_pelz_uri_key_UID(key_id_data, &server_key_id, &server_key_id_len) != 0)
      {
        pelz_log(LOG_ERR, "Failed to extract key UID from pelz uri");
        break;
      }

      pelz_log(LOG_DEBUG, "Common Name: %.*s, %d", common_name_len, common_name, common_name_len);
      pelz_log(LOG_DEBUG, "Port Number: %d", port);
      pelz_log(LOG_DEBUG, "Key UID: %.*s", server_key_id, server_key_id);
      key_table_add_from_server(eid, &status, key_id, common_name_len, (const char *) common_name, port,
        server_key_id_len, server_key_id);
      free(common_name);
      free(server_key_id);
      switch (status)
      {
      case ERR:
        {
          pelz_log(LOG_ERR, "Failed to load key to table");
          return_value = 1;
          break;
        }
      case ERR_MEM:
        {
          pelz_log(LOG_ERR, "Key Table memory allocation greater than specified limit.");
          return_value = 1;
          break;
        }
      case ERR_REALLOC:
        {
          pelz_log(LOG_ERR, "Key List Space Reallocation Error");
          return_value = 1;
          break;
        }
      case NO_MATCH:
        {
           pelz_log(LOG_ERR, "Certificate or Private Key not matched");
          return_value = 1;
          break;
        }
      case RET_FAIL:
        {
          pelz_log(LOG_ERR, "Key Retrieve Failure");
          return_value = 1;
          break;
        }
      case OK:
        {
          pelz_log(LOG_DEBUG, "Key added to table.");
          return_value = 0;
          break;
        }
      default:
        {
          return_value = 1;
          break;
        }
      }
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

int write_to_pipe_fd(int fd, char *msg)
{
  int msg_len;
  int bytes_written;

  msg_len = strlen(msg);
  bytes_written = write(fd, msg, msg_len);
  if (bytes_written == msg_len)
  {
    return 0;
  }
  else
  {
    pelz_log(LOG_ERR, "Error writing to pipe");
    return 1;
  }
}

int write_to_pipe(char *pipe, char *msg)
{
  int fd;
  int ret;

  fd = open_write_pipe(pipe);
  if (fd == -1)
  {
    pelz_log(LOG_ERR, "Error opening pipe");
    perror("open");
    return 1;
  }

  ret = write_to_pipe_fd(fd, msg);

  if (close(fd) == -1)
  {
    pelz_log(LOG_ERR, "Error closing pipe");
  }
  return ret;
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
    perror("open");
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
    return 1;
  }

  if (ret > 0)
  {
    *msg = (char *) calloc(ret + 1, sizeof(char));
    memcpy(*msg, buf, ret);
  }
  else if (ret < 0)
  {
    pelz_log(LOG_ERR, "Pipe read failed");
    return 1;
  }
  else
  {
    pelz_log(LOG_DEBUG, "No read of pipe");
    *msg = NULL;
  }
  return 0;
}

int read_listener(int fd)
{
  fd_set set;
  struct timeval timeout;
  int rv;
  char msg[BUFSIZE];
  int line_start, line_len, i;
  int bytes_read;

  FD_ZERO(&set);      // clear the set
  FD_SET(fd, &set);   // add file descriptor to the set

  timeout.tv_sec = 5;
  timeout.tv_usec = 0;

  // Read from the pipe until we see an END terminator, get an error, or time out
  while (true)
  {
    rv = select(fd + 1, &set, NULL, NULL, &timeout);
    if (rv == -1)
    {
      pelz_log(LOG_DEBUG, "Error in timeout of pipe.");
      fprintf(stdout, "Error in timeout of pipe.\n");
      close(fd);
      return 1;
    }
    else if (rv == 0)
    {
      pelz_log(LOG_DEBUG, "No response received from pelz-service.");
      fprintf(stdout, "No response received from pelz-service.\n");
      close(fd);
      return 1;
    }

    bytes_read = read(fd, msg, BUFSIZE);
    if (bytes_read < 0)
    {
      if (errno == EWOULDBLOCK) {
        // This happens occasionally because select is sometimes wrong
        continue;
      }
      pelz_log(LOG_ERR, "Pipe read failed");
      perror("read");
      close(fd);
      return 1;
    }

    // The received data can contain multiple message components separated by newlines
    line_start = 0;
    for (i=0; i<bytes_read; i++)
    {
      if (msg[i] == '\n')
      {
        line_len = i - line_start;

        if (line_len == 3 && memcmp(&msg[line_start], "END", 3) == 0)
        {
          pelz_log(LOG_DEBUG, "Got END message");
          close(fd);
          return 0;
        }
        else
        {
          pelz_log(LOG_DEBUG, "%.*s", line_len, &msg[line_start]);
          fprintf(stdout, "%.*s\n", line_len, &msg[line_start]);
        }

        line_start = i + 1;
      }
      else if (i == bytes_read - 1)
      {
        line_len = i - line_start;
        pelz_log(LOG_ERR, "Incomplete response message - missing newline: %.*s.", line_len, &msg[line_start]);
        close(fd);
        return 1;
      }
    }
  }
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
  TableResponseStatus ret;
  charbuf key_id;
  charbuf server_id;
  uint64_t handle;
  size_t count;

  pelz_log(LOG_DEBUG, "Token num: %d", num_tokens);
  if (num_tokens < 3)
  {
    return INVALID;
  }

/*
 *  -1    exit                      Terminate running pelz-service
 *  -2    keytable remove key       Removes a key with a specified id
 *  -3    keytable remove all keys  Removes all keys
 *  -4    keytable list             Outputs a list of key <id> in Key Table
 *  -5    pki load cert             Loads a server certificate
 *  -6    pki load private          Loads a private key for connections to key servers
 *  -7    pki cert list             Outputs a list of certificate <CN> in Server Table
 *  -8    pki remove cert           Removes a server certificate   
 *  -9    pki remove all certs      Removes all server certificates
 *  -10   pki remove cert           Removes the private key   
 */
  switch (atoi(tokens[1]))
  {
  case 1:
    if (unlink(PELZSERVICE) == 0)
    {
      pelz_log(LOG_INFO, "Pipe deleted successfully");
    }
    else
    {
      pelz_log(LOG_INFO, "Failed to delete the pipe");
    }
    return EXIT;
  case 2:
    if (num_tokens != 4)
    {
      return INVALID;
    }

    key_id = new_charbuf(strlen(tokens[3]));
    if (key_id.len != strlen(tokens[3]))
    {
      pelz_log(LOG_ERR, "Charbuf creation error.");
      return ERR_CHARBUF;
    }
    memcpy(key_id.chars, tokens[3], key_id.len);
    table_delete(eid, &ret, KEY, key_id);
    if (ret == NO_MATCH)
    {
      pelz_log(LOG_ERR, "Delete Key ID from Key Table Failure: %.*s", (int) key_id.len, key_id.chars);
      pelz_log(LOG_ERR, "Key ID not found");
      free_charbuf(&key_id);
      return RM_KEK_FAIL;
    }
    else if (ret == ERR_REALLOC)
    {
      pelz_log(LOG_ERR, "Delete Key ID from Key Table Failure: %.*s", (int) key_id.len, key_id.chars);
      pelz_log(LOG_ERR, "Key Table reallocation failure");
      free_charbuf(&key_id);
      return RM_KEK_FAIL;
    }
    else
    {
      pelz_log(LOG_INFO, "Delete Key ID form Key Table: %.*s", (int) key_id.len, key_id.chars);
      free_charbuf(&key_id);
      return RM_KEK;
    }
  case 3:
    table_destroy(eid, &ret, KEY);
    if (ret != OK)
    {
      pelz_log(LOG_ERR, "Key Table Destroy Failure");
      return KEK_TAB_DEST_FAIL;
    }
    pelz_log(LOG_INFO, "Key Table Destroyed and Re-Initialize");
    return RM_KEK_ALL;
  case 4:
    //Get the number of key table entries
    table_id_count(eid, &ret, KEY, &count);
    if (count == 0)
    {
      pelz_log(LOG_INFO, "No entries in Key Table.");
      return NO_KEY_LIST;
    }
    return KEY_LIST;
  case 5:
    if (num_tokens != 4)
    {
      return INVALID;
    }

    if (pelz_load_file_to_enclave(tokens[3], &handle))
    {
      pelz_log(LOG_INFO, "Invalid extension for load cert call");
      pelz_log(LOG_DEBUG, "Path: %s", tokens[3]);
      return INVALID_EXT_CERT;
    }
    server_table_add(eid, &ret, handle);
    if (ret != OK)
    {
      pelz_log(LOG_ERR, "Add cert failure");
      switch (ret)
      {
      case ERR_REALLOC:
        pelz_log(LOG_ERR, "Server Table memory allocation greater then specified limit.");
        break;
      case ERR_BUF:
        pelz_log(LOG_ERR, "Charbuf creation error.");
        break;
      case ERR_X509:
        pelz_log(LOG_ERR, "X509 allocation error.");
        return X509_FAIL;
      case RET_FAIL:
        pelz_log(LOG_ERR, "Failure to retrieve data from unseal table.");
        break;
      case NO_MATCH:
        pelz_log(LOG_ERR, "Cert entry and Server ID lookup do not match.");
        break;
      case MEM_ALLOC_FAIL:
        pelz_log(LOG_ERR, "Cert List Space Reallocation Error");
        break;
      default:
        pelz_log(LOG_ERR, "Server return not defined");
      }
      return ADD_CERT_FAIL;
    }
    return LOAD_CERT;
  case 6:
    if (num_tokens != 4)
    {
      return INVALID;
    }
    if (pelz_load_file_to_enclave(tokens[3], &handle))
    {
      pelz_log(LOG_INFO, "Invalid extension for load private call");
      pelz_log(LOG_DEBUG, "Path: %s", tokens[3]);
      return INVALID_EXT_PRIV;
    }
    private_pkey_add(eid, &ret, handle);
    if (ret != OK)
    {
      pelz_log(LOG_ERR, "Add private pkey failure");
      switch (ret)
      {
      case ERR_X509:
        pelz_log(LOG_ERR, "X509 allocation error.");
        return X509_FAIL;
      case RET_FAIL:
        pelz_log(LOG_ERR, "Failure to retrieve data from unseal table.");
        break;
      default:
        pelz_log(LOG_ERR, "Private pkey add return not defined");
      }
      return ADD_PRIV_FAIL;
    }
    return LOAD_PRIV;
  case 7:
    //Get the number of server table entries
    table_id_count(eid, &ret, SERVER, &count);
    if (count == 0)
    {
      pelz_log(LOG_INFO, "No entries in Server Table.");
      return NO_SERVER_LIST;
    }
    return SERVER_LIST;
  case 8:
    if (num_tokens != 4)
    {
      return INVALID;
    }
    server_id = new_charbuf(strlen(tokens[3]));
    if (server_id.len != strlen(tokens[3]))
    {
      pelz_log(LOG_ERR, "Charbuf creation error.");
      return ERR_CHARBUF;
    }
    memcpy(server_id.chars, tokens[3], server_id.len);
    table_delete(eid, &ret, SERVER, server_id);
    if (ret == NO_MATCH)
    {
      pelz_log(LOG_ERR, "Delete Server ID from Server Table Failure: %.*s", (int) server_id.len, server_id.chars);
      pelz_log(LOG_ERR, "Server ID not found");
      free_charbuf(&server_id);
      return RM_CERT_FAIL;
    }
    else if (ret == ERR_REALLOC)
    {
      pelz_log(LOG_ERR, "Delete Server ID from Server Table Failure: %.*s", (int) server_id.len, server_id.chars);
      pelz_log(LOG_ERR, "Server Table reallocation failure");
      free_charbuf(&server_id);
      return RM_CERT_FAIL;
    }
    else
    {
      pelz_log(LOG_INFO, "Delete Server ID form Server Table: %.*s", (int) server_id.len, server_id.chars);
      free_charbuf(&server_id);
      return RM_CERT;
    }
  case 9:
    table_destroy(eid, &ret, SERVER);
    if (ret != OK)
    {
      pelz_log(LOG_ERR, "Server Table Destroy Failure");
      return CERT_TAB_DEST_FAIL;
    }
    pelz_log(LOG_INFO, "Server Table Destroyed and Re-Initialized");
    return RM_ALL_CERT;
  case 10:
    //Free private pkey to remove pkey
    private_pkey_free(eid, &ret);
    if (ret != OK)
    {
      pelz_log(LOG_ERR, "PKEY Free Failure");
      return RM_PRIV_FAIL;
    }

    //Re-initializing pkey so new pkey can be loaded
    private_pkey_init(eid, &ret);
    if (ret != OK)
    {
      pelz_log(LOG_ERR, "PKEY Re-init Failure");
      return RM_PRIV_FAIL;
    }
    return RM_PRIV;
  default:
    pelz_log(LOG_ERR, "Pipe command invalid: %s %s", tokens[0], tokens[1]);
    return INVALID;
  }

  return INVALID;
}

int open_read_pipe(char *name)
{
  if (file_check(name))
  {
    pelz_log(LOG_ERR, "Pipe not found");
    return -1;
  }

  return open(name, O_RDONLY | O_NONBLOCK);
}

int open_write_pipe(char *name)
{
  if (file_check(name))
  {
    pelz_log(LOG_ERR, "Pipe not found");
    return -1;
  }

  // Opening in nonblocking mode will fail if the other end of the pipe is not yet open for reading.
  return open(name, O_WRONLY | O_NONBLOCK);
}

int remove_pipe(char *name)
{
  //Exit and remove FIFO
  if (unlink(name) == 0)
  {
    pelz_log(LOG_DEBUG, "Pipe deleted successfully");
  }
  else
  {
    pelz_log(LOG_DEBUG, "Failed to delete the pipe");
  }
  return 0;
}
