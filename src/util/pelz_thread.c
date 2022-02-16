#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <kmyth/formatting_tools.h>

#include "charbuf.h"
#include "pelz_log.h"
#include "pelz_socket.h"
#include "pelz_json_parser.h"
#include "pelz_io.h"
#include "pelz_request_handler.h"
#include "pelz_thread.h"

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"

#define BUFSIZE 1024
#define MODE 0600

void *pelz_listener(void *args)
{
  ListenerThreadArgs *thread_args = (ListenerThreadArgs *) args;

  thread_args->return_value = 0;

  if (file_check(thread_args->pipe))
  {
    pelz_log(LOG_ERR, "Pipe not found");
    thread_args->return_value = 1;
    pthread_mutex_unlock(thread_args->listener_mutex);
    return NULL;
  }

  int fd = open(thread_args->pipe, O_RDONLY | O_NONBLOCK);

  if (fd == -1)
  {
    pelz_log(LOG_ERR, "Error opening pipe for reading");
    thread_args->return_value = 1;
    pthread_mutex_unlock(thread_args->listener_mutex);
    return NULL;
  }

  int poll = epoll_create1(0);

  if (poll == -1)
  {
    pelz_log(LOG_ERR, "Unable to create epoll file descriptor.");
    thread_args->return_value = 1;
    pthread_mutex_unlock(thread_args->listener_mutex);
    close(fd);
    return NULL;
  }

  char msg[BUFSIZE];
  int msg_count;
  struct epoll_event listener;
  struct epoll_event listener_events[1];

  listener.events = EPOLLIN;
  listener.data.fd = fd;

  if (epoll_ctl(poll, EPOLL_CTL_ADD, fd, &listener))
  {
    pelz_log(LOG_ERR, "Failed to poll pipe.");
    close(fd);
    close(poll);
    thread_args->return_value = 1;
    pthread_mutex_unlock(thread_args->listener_mutex);
    return NULL;
  }

  pthread_mutex_unlock(thread_args->listener_mutex);
  int event_count = epoll_wait(poll, listener_events, 1, 15000);

  if (event_count == 0)
  {
    pelz_log(LOG_DEBUG, "No response received from pelz-service.");
    fprintf(stdout, "No response received from pelz-service.\n");
    thread_args->return_value = 1;
  }
  else if (event_count == -1)
  {
    pelz_log(LOG_DEBUG, "Error in poll of pipe.");
    fprintf(stdout, "Error in poll of pipe.\n");
    thread_args->return_value = 1;
  }
  else
  {
    int bytes_read = read(listener_events[0].data.fd, msg, BUFSIZE);
    msg_count = atoi(msg);

    struct epoll_event msg_events[msg_count];

    while (msg_count > 0)
    {
      event_count = epoll_wait(poll, msg_events, msg_count, 1000);

      if (event_count == 0) 
      {
        pelz_log(LOG_DEBUG, "No response received from pelz-service.");
	fprintf(stdout, "No response received from pelz-service.\n");
	thread_args->return_value = 1;
      }
      else if (event_count == -1)
      {
        pelz_log(LOG_DEBUG, "Error in poll of pipe.");
	fprintf(stdout, "Error in poll of pipe.\n");
	thread_args->return_value = 1;
      }
      else
      {
        for (int i = 0; i < event_count; i++)
	{	
          bytes_read = read(msg_events[i].data.fd, msg, BUFSIZE);
	  if (bytes_read > 0)
	  {
      	    pelz_log(LOG_DEBUG, "%.*s", bytes_read, msg);
	    fprintf(stdout, "%.*s\n", bytes_read, msg);
	    msg_count -= 1;
	  }
	}
      }
    }
  }
  close(fd);
  close(poll);
  return NULL;
}

void *fifo_thread_process(void *arg)
{
  ThreadArgs *threadArgs = (ThreadArgs *) arg;
  pthread_mutex_t lock = threadArgs->lock;

  TableResponseStatus status;
  char *msg = NULL;
  char **tokens;
  size_t num_tokens = 0;
  int ret = 0;
  size_t count;
  size_t list_num = 0;
  charbuf id;

  const char *resp_str[27] =
    { "Invalid pipe command received by pelz-service.",
      "Successfully initiated termination of pelz-service.",
      "Unable to read file",
      "TPM unseal failed",
      "SGX unseal failed",
      "Failure to add cert",
      "Successfully loaded certificate file into pelz-service.",
      "Invalid certificate file, unable to load.",
      "Failure to add private",
      "Successfully loaded private key into pelz-service.",
      "Invalid private key file, unable to load.",
      "Failure to remove cert",
      "Removed cert",
      "Server Table Destroy Failure",
      "All certs removed",
      "Failure to remove key",
      "Removed key",
      "Key Table Destroy Failure",
      "All keys removed",
      "Charbuf creation error.",
      "Unable to load file. Files must originally be in the DER format prior to sealing.",
      "Failure to remove private pkey",
      "Removed private pkey",
      "No entries in Key Table.",
      "Key Table List:",
      "No entries in Server Table.",
      "PKI Certificate List:"
  };

  if (mkfifo(PELZSERVICEIN, MODE) == 0)
  {
    pelz_log(LOG_DEBUG, "Pipe created successfully");
  }
  else
  {
    pelz_log(LOG_DEBUG, "Error: %s", strerror(errno));
  }

  do
  {
    pthread_mutex_lock(&lock);
    if (read_from_pipe((char *) PELZSERVICEIN, &msg))
    {
      break;
    }

    /*
     * Tokens come out in the following format:
     *
     * token[0] is the program that called it (e.g., pelz)
     * token[1] is the command parsed below
     * token[2-n] are the command inputs. An example for load cert would be:
     *
     * token[0] = pelz
     * token[1] = 2
     * token[2] = path/to/input
     * token[3] = path/to/output
     *
     */
    if (tokenize_pipe_message(&tokens, &num_tokens, msg, strlen(msg)))
    {
      free(msg);
      pthread_mutex_unlock(&lock);
      continue;
    }
    free(msg);

    ret = parse_pipe_message(tokens, num_tokens);
    switch (ret)
    {
      case KEY_LIST:
	table_id_count(eid, &status, KEY, &list_num);
        if (status != OK)
        {
          pelz_log(LOG_DEBUG, "Error retrieving Key Table count.");
          break;
        }

	msg = (char *) calloc(10, sizeof(char));
	sprintf(msg, "%d", (int) (list_num + 1));
	pelz_log(LOG_DEBUG, "%s", msg);
	if (write_to_pipe(tokens[2], msg))
        {
           pelz_log(LOG_DEBUG, "Unable to send response to pelz cmd.");
        }
        else
        {
          pelz_log(LOG_DEBUG, "Pelz-service responses sent to pelz cmd.");
        }
	free(msg);

	pelz_log(LOG_DEBUG, "%s", resp_str[ret]);
	if (write_to_pipe(tokens[2], (char *) resp_str[ret]))
        {
           pelz_log(LOG_DEBUG, "Unable to send response to pelz cmd.");
        }
        else
        {
          pelz_log(LOG_DEBUG, "Pelz-service responses sent to pelz cmd.");
        }

        for (count = 0; count < list_num; count++)
        {
          table_id(eid, &status, KEY, count, &id);
          if (status != OK)
          {
            pelz_log(LOG_DEBUG, "Error retrieving Key Table <ID> from index %d.", count);
            continue;
          }

          msg = (char *) calloc((id.len), sizeof(char));
          if (!msg)
          {
            pelz_log(LOG_ERR, "Unable to allocate memory.");
            continue;
          }
          memcpy(msg, id.chars, id.len);

          if (write_to_pipe(tokens[2], msg))
          {
            pelz_log(LOG_DEBUG, "Unable to send response to pelz cmd.");
          }
          free(msg);
        }
        break;
      case SERVER_LIST:
	table_id_count(eid, &status, SERVER, &list_num);
        if (status != OK)
        {
          pelz_log(LOG_DEBUG, "Error retrieving Server Table count.");
          break;
        }

	msg = (char *) calloc(10, sizeof(char));
	sprintf(msg, "%d", (int) (list_num + 1));
	pelz_log(LOG_DEBUG, "%s", msg);
        if (write_to_pipe(tokens[2], msg))
        {
           pelz_log(LOG_DEBUG, "Unable to send response to pelz cmd.");
        }
        else
        {
          pelz_log(LOG_DEBUG, "Pelz-service responses sent to pelz cmd.");
        }
        free(msg);

	pelz_log(LOG_DEBUG, "%s", resp_str[ret]);
        if (write_to_pipe(tokens[2], (char *) resp_str[ret]))
        {
           pelz_log(LOG_DEBUG, "Unable to send response to pelz cmd.");
        }
        else
        {
          pelz_log(LOG_DEBUG, "Pelz-service responses sent to pelz cmd.");
        }

        for (count = 0; count < list_num; count++)
        {
          table_id(eid, &status, SERVER, count, &id);
          if (status != OK)
          {
            pelz_log(LOG_DEBUG, "Error retrieving Server Table <ID> from index %d.", count);
            continue;
          }

          msg = (char *) calloc((id.len), sizeof(char));
          if (!msg)
          {
            pelz_log(LOG_ERR, "Unable to allocate memory.");
            continue;
          }
          memcpy(msg, id.chars, id.len);

          if (write_to_pipe(tokens[2], msg))
          {
            pelz_log(LOG_DEBUG, "Unable to send response to pelz cmd.");
          }
          free(msg);
        }
	break;
      default:
	if (write_to_pipe(tokens[2], (char *) "1"))
        {
           pelz_log(LOG_DEBUG, "Unable to send response to pelz cmd.");
        }
        else
        {
          pelz_log(LOG_DEBUG, "Pelz-service responses sent to pelz cmd.");
        }
       	if (write_to_pipe(tokens[2], (char *) resp_str[ret]))
        {
           pelz_log(LOG_DEBUG, "Unable to send response to pelz cmd.");
        }
        else
        {
          pelz_log(LOG_DEBUG, "Pelz-service responses sent to pelz cmd.");
        }
    }

    //Free the tokens
    for (size_t i = 0; i < num_tokens; i++)
    {
      free(tokens[i]);
    }
    free(tokens);
    pthread_mutex_unlock(&lock);
    
    if (ret == EXIT || ret == KEK_TAB_DEST_FAIL || ret == CERT_TAB_DEST_FAIL)
    {
      break;
    }
  }
  while (true);
  global_pipe_reader_active = false;
  return NULL;
}

void thread_process(void *arg)
{
  ThreadArgs *threadArgs = (ThreadArgs *) arg;
  int new_socket = threadArgs->socket_id;
  pthread_mutex_t lock = threadArgs->lock;

  charbuf request;
  charbuf message;
  RequestResponseStatus status;
  const char *err_message;

  while (!pelz_key_socket_check(new_socket))
  {
    //Receiving request and Error Checking
    if (pelz_key_socket_recv(new_socket, &request))
    {
      pelz_log(LOG_ERR, "%d::Error Receiving Request", new_socket);
      while (!pelz_key_socket_check(new_socket))
      {
        continue;
      }
      pelz_key_socket_close(new_socket);
      return;
    }

    pelz_log(LOG_DEBUG, "%d::Request & Length: %.*s, %d", new_socket, (int) request.len, request.chars, (int) request.len);

    RequestType request_type = REQ_UNK;

    charbuf key_id;
    charbuf data_in;
    charbuf data_out;

    charbuf data;
    charbuf output;

    //Parse request for processing
    if (request_decoder(request, &request_type, &key_id, &data_in))
    {
      err_message = "Missing Data";
      error_message_encoder(&message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %.*s, %d", new_socket, (int) message.len, message.chars, (int) message.len);
      pelz_key_socket_close(new_socket);
      free_charbuf(&request);
      return;
    }

    free_charbuf(&request);

    decodeBase64Data(data_in.chars, data_in.len, &data.chars, &data.len);
    free_charbuf(&data_in);

    pthread_mutex_lock(&lock);
    pelz_request_handler(eid, &status, request_type, key_id, data, &output);
    if (status == KEK_NOT_LOADED)
    {
      if (key_load(key_id) == 0)
      {
        pelz_request_handler(eid, &status, request_type, key_id, data, &output);
      }
      else
      {
        status = KEK_LOAD_ERROR;
      }
    }
    pthread_mutex_unlock(&lock);
    free_charbuf(&data);

    if (status != REQUEST_OK)
    {
      pelz_log(LOG_ERR, "%d::Service Error\nSend error message.", new_socket);
      switch (status)
      {
      case KEK_LOAD_ERROR:
        err_message = "Key not added";
        break;
      case KEY_OR_DATA_ERROR:
        err_message = "Key or Data Error";
        break;
      case ENCRYPT_ERROR:
        err_message = "Encrypt Error";
        break;
      case DECRYPT_ERROR:
        err_message = "Decrypt Error";
        break;
      case REQUEST_TYPE_ERROR:
        err_message = "Request Type Error";
        break;
      case CHARBUF_ERROR:
        err_message = "Charbuf Error";
        break;
      default:
        err_message = "Unrecognized response";
      }
      error_message_encoder(&message, err_message);
    }
    else
    {
      encodeBase64Data(output.chars, output.len, &data_out.chars, &data_out.len);
      if (strlen((char *) data_out.chars) != data_out.len)
      {
        data_out.chars[data_out.len] = 0;
      }
      message_encoder(request_type, key_id, data_out, &message);
      pelz_log(LOG_DEBUG, "%d::Message Encode Complete", new_socket);
      pelz_log(LOG_DEBUG, "%d::Message: %.*s, %d", new_socket, (int) message.len, message.chars, (int) message.len);
    }
    free_charbuf(&key_id);
    free_charbuf(&data_out);
    free_charbuf(&output);

    pelz_log(LOG_DEBUG, "%d::Message & Length: %.*s, %d", new_socket, (int) message.len, message.chars, (int) message.len);
    //Send processed request back to client
    if (pelz_key_socket_send(new_socket, message))
    {
      pelz_log(LOG_ERR, "%d::Socket Send Error", new_socket);
      free_charbuf(&message);
      while (!pelz_key_socket_check(new_socket))
      {
        continue;
      }
      pelz_key_socket_close(new_socket);
      return;
    }
    free_charbuf(&message);
  }
  pelz_key_socket_close(new_socket);
  return;
}
