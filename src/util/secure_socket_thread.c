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
#include "key_load.h"
#include "pelz_service.h"
#include "pelz_request_handler.h"
#include "secure_socket_thread.h"

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include ENCLAVE_HEADER_UNTRUSTED

#define BUFSIZE 1024
#define MODE 0600

static void *secure_process_wrapper(void *arg)
{
  secure_socket_process(arg);
  pthread_exit(NULL);
}

void *secure_socket_thread(void *arg)
{
  ThreadArgs *threadArgs = (ThreadArgs *) arg;
  int port = threadArgs->port;
  int max_requests = threadArgs->max_requests;
  pthread_mutex_t lock = threadArgs->lock;

  ThreadArgs processArgs;
  pthread_t stid[max_requests];
  int socket_id = 0;
  int socket_listen_id;

  //Initializing Socket
  if (pelz_key_socket_init(max_requests, port, &socket_listen_id))
  {
    pelz_log(LOG_ERR, "Socket Initialization Error");
    return NULL;
  }
  pelz_log(LOG_DEBUG, "Secure socket on port %d created with listen_id of %d", port, socket_listen_id);

  do
  {
    if (pelz_key_socket_accept(socket_listen_id, &socket_id))
    {
      pelz_log(LOG_ERR, "Socket Client Connection Error");
      continue;
    }

    if (socket_id == 0)         //This is to reset the while loop if select() times out
    {
      continue;
    }
    pelz_log(LOG_DEBUG, "Secure socket connection accepted");

    if (socket_id > max_requests)
    {
      pelz_log(LOG_WARNING, "%d::Over max socket requests.", socket_id);
      pelz_key_socket_close(socket_id);
      continue;
    }

    processArgs.lock = lock;
    processArgs.socket_id = socket_id;
    if (pthread_create(&stid[socket_id], NULL, secure_process_wrapper, &processArgs) != 0)
    {
      pelz_log(LOG_WARNING, "%d::Failed to create thread.", socket_id);
      pelz_key_socket_close(socket_id);
      continue;
    }

    pelz_log(LOG_INFO, "Secure Socket Thread %d, %d", (int) stid[socket_id], socket_id);
  }
  while (socket_listen_id >= 0 && socket_id <= (max_requests + 1) && global_pipe_reader_active);
  pelz_key_socket_teardown(&socket_listen_id);
  return NULL;
}

//This function will need to be changed with the attestation handshake and process flow
void *secure_socket_process(void *arg)
{
  ThreadArgs *processArgs = (ThreadArgs *) arg;
  int new_socket = processArgs->socket_id;
  pthread_mutex_t lock = processArgs->lock;

  charbuf request;
  charbuf message;
  RequestResponseStatus status;
  const char *err_message;

  //Attestation handshake function should be added here in the process flow

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
      return NULL;
    }

    pelz_log(LOG_DEBUG, "%d::Request & Length: %.*s, %d", new_socket, (int) request.len, request.chars, (int) request.len);

    RequestType request_type = REQ_UNK;

    charbuf key_id;
    charbuf request_sig;
    charbuf requestor_cert;
    charbuf cipher_name;

    charbuf raw_output = new_charbuf(0);
    charbuf encoded_output = new_charbuf(0);
    charbuf raw_input_data = new_charbuf(0);
    charbuf encoded_input_data = new_charbuf(0);
    charbuf raw_tag = new_charbuf(0);
    charbuf encoded_tag = new_charbuf(0);
    charbuf raw_iv = new_charbuf(0);
    charbuf encoded_iv = new_charbuf(0);

    //Parse request for processing
    if (request_decoder(request, &request_type, &key_id, &cipher_name, &encoded_iv, &encoded_tag, &raw_input_data, &request_sig, &requestor_cert))
    {
      err_message = "Missing Data";
      error_message_encoder(&message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %.*s, %d", new_socket, (int) message.len, message.chars, (int) message.len);
      pelz_key_socket_close(new_socket);
      free_charbuf(&request);
      return NULL;
    }
    free_charbuf(&request);

    pthread_mutex_lock(&lock);
    switch(request_type)
    {
    case REQ_ENC:
      pelz_encrypt_request_handler(eid, &status, request_type, key_id, cipher_name, raw_input_data, &raw_output, &raw_iv, &raw_tag);
      if (status == KEK_NOT_LOADED)
      {
	if (key_load(key_id) == 0)
        {
          pelz_encrypt_request_handler(eid, &status, request_type, key_id, cipher_name, raw_input_data, &raw_output, &raw_iv, &raw_tag);
        }
        else
        {
          status = KEK_LOAD_ERROR;
        }
      }
      break;
    case REQ_DEC:
      decodeBase64Data(encoded_tag.chars, encoded_tag.len, &raw_tag.chars, &raw_tag.len);
      decodeBase64Data(encoded_iv.chars, encoded_iv.len, &raw_iv.chars, &raw_iv.len);
      pelz_decrypt_request_handler(eid, &status, request_type, key_id, cipher_name, raw_input_data, raw_iv, raw_tag, &raw_output);
      if (status == KEK_NOT_LOADED)
      {
	if (key_load(key_id) == 0)
        {
          pelz_decrypt_request_handler(eid, &status, request_type, key_id, cipher_name, raw_input_data, raw_iv, raw_tag, &raw_output);
        }
        else
        {
          status = KEK_LOAD_ERROR;
        }
      }
      break;
    default:
      status = REQUEST_TYPE_ERROR;
    }
    pthread_mutex_unlock(&lock);
    free_charbuf(&raw_input_data);

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
      encodeBase64Data(raw_output.chars, raw_output.len, &encoded_output.chars, &encoded_output.len);
      encodeBase64Data(raw_tag.chars, raw_tag.len, &encoded_tag.chars, &encoded_tag.len);
      encodeBase64Data(raw_iv.chars, raw_iv.len, &encoded_iv.chars, &encoded_iv.len);
      if (strlen((char *) encoded_output.chars) != encoded_output.len)
      {
        encoded_output.chars[encoded_output.len] = 0;
      }
      message_encoder(request_type, key_id, cipher_name, encoded_iv, encoded_tag, encoded_output, &message);
      pelz_log(LOG_DEBUG, "%d::Message Encode Complete", new_socket);
      pelz_log(LOG_DEBUG, "%d::Message: %.*s, %d", new_socket, (int) message.len, message.chars, (int) message.len);
    }
    free_charbuf(&key_id);
    free_charbuf(&encoded_input_data);
    free_charbuf(&raw_output);
    free_charbuf(&encoded_output);
    free_charbuf(&raw_iv);
    free_charbuf(&raw_tag);
    free_charbuf(&encoded_iv);
    free_charbuf(&encoded_tag);
    free_charbuf(&cipher_name);

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
      return NULL;
    }
    free_charbuf(&message);
  }
  pelz_key_socket_close(new_socket);
  return NULL;
}

