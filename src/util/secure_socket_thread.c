/* Note: much of this code is adapted from linux-sgx/SampleCode/LocalAttestation/AppResponder/CPTask.cpp */

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
#include "secure_socket_ecdh.h"

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include ENCLAVE_HEADER_UNTRUSTED


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

//Receive message from client
int recv_message(int socket_id, FIFO_MSG ** message)
{
  int bytes_received;
  FIFO_MSG_HEADER header;
  FIFO_MSG *msg;

  pelz_log(LOG_DEBUG, "%d::Reading message header...", socket_id);

  bytes_received = recv(socket_id, &header, sizeof(FIFO_MSG_HEADER), 0);

  if (bytes_received != sizeof(FIFO_MSG_HEADER))
  {
    pelz_log(LOG_ERR, "%d::Received incomplete message header.", socket_id);
    return (1);
  }

  if (header.size > MAX_MSG_SIZE)
  {
    pelz_log(LOG_ERR, "%d::Received message with invalid size.", socket_id);
    return (1);
  }

  header.sockfd = socket_id;  // Save current socket fd in header

  msg = malloc(sizeof(FIFO_MSG_HEADER) + header.size + 1);

  if (header.size > 0)
  {
    bytes_received = recv(socket_id, msg->msgbuf, header.size, 0);
    if (bytes_received != header.size)
    {
      pelz_log(LOG_ERR, "%d::Received incomplete message content.", socket_id);
      return (1);
    }
  }

  msg->msgbuf[header.size] = '\0';  // Add null terminator

  pelz_log(LOG_INFO, "%d::Received message with %d bytes.", socket_id, header.size);

  *message = msg;

  return (0);
}

//This function will need to be changed with the attestation handshake and process flow
void *secure_socket_process(void *arg)
{
  ThreadArgs *processArgs = (ThreadArgs *) arg;
  int sockfd = processArgs->socket_id;
  pthread_mutex_t lock = processArgs->lock;

  charbuf request;
  charbuf message;
  RequestResponseStatus status;
  const char *err_message;

  // TODO: keep track of session ID, and other unprotected session metadata

  // TODO: Check attestation
  // TODO: Check attestation cert

  FIFO_MSG * message = NULL;

  while (!pelz_key_socket_check(sockfd))
  {
    //Receiving request and Error Checking
    if (recv_message(sockfd, &message))
    {
      pelz_log(LOG_ERR, "%d::Error receiving message", sockfd);
      while (!pelz_key_socket_check(sockfd))
      {
        continue;
      }
      pelz_key_socket_close(sockfd);
      return NULL;
    }

    pelz_log(LOG_DEBUG, "%d::Request type & Length: %d, %d", sockfd, message->header.type, message->header.size);

    if (handle_message(sockfd, message))
    {
      pelz_log(LOG_ERR, "%d::Error handling message", sockfd);
      return NULL;
    }

    free(message);
    message = NULL;
  }

  return NULL;
}

// This function will need to be moved into the enclave
int handle_pelz_request(charbuf request)
{
    // TODO:
    // Unwrap message
    // Extract encrypted parameters from JSON
    // Handle request + gen response (ecall)
    // Construct response JSON
    // Wrap + send message

    RequestType request_type = REQ_UNK;

    charbuf key_id;
    charbuf data_in;
    charbuf data_out;
    charbuf request_sig;
    charbuf requestor_cert;

    charbuf data;
    charbuf output;

    //Parse request for processing
    if (request_decoder(request, &request_type, &key_id, &data_in, &request_sig, &requestor_cert))
    {
      err_message = "Missing Data";
      error_message_encoder(&message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %.*s, %d", new_socket, (int) message.len, message.chars, (int) message.len);
      pelz_key_socket_close(new_socket);
      free_charbuf(&request);
      return NULL;
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
      return NULL;
    }
    free_charbuf(&message);
  }
  pelz_key_socket_close(new_socket);
  return NULL;
}
