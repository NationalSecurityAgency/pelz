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
    pelz_log(LOG_ERR, "Create source BIO error.");
    BIO_free_all(bio64);
    return 1;
  }

  bio64 = BIO_push(bio64, bio_mem);
  int bytes_read = BIO_read(bio64, *raw_data, base64_data_size);

  if (bytes_read < 0)
  {
    pelz_log(LOG_ERR, "Error reading bytes from BIO chain.");
    BIO_free_all(bio64);
    return 1;
  }

  (*raw_data)[bytes_read] = '\0';
  *raw_data_size = bytes_read;
  BIO_free_all(bio64);
  return (0);
}

int write_to_pipe(char *msg)
{
  int fd;
  int ret;

  if (file_check((char*) PELZFIFO))
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
  ret = write(fd, msg, strlen(msg)+1);
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
    pelz_log(LOG_DEBUG, "Pipe message: %d, %c, %s", strlen(msg), opt,  msg);
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
            if(ret)
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

