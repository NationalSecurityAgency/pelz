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
  size_t bytes_received;
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

  msg = (FIFO_MSG *) malloc(sizeof(FIFO_MSG_HEADER) + header.size);

  memcpy(msg, &header, sizeof(FIFO_MSG_HEADER));

  if (header.size > 0)
  {
    bytes_received = recv(socket_id, msg->msgbuf, header.size, 0);
    if (bytes_received != header.size)
    {
      pelz_log(LOG_ERR, "%d::Received incomplete message content.", socket_id);
      return (1);
    }
  }

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

  int ret;

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

    pthread_mutex_lock(&lock);
    ret = handle_message(sockfd, message);
    pthread_mutex_unlock(&lock);

    free(message);
    message = NULL;

    if (ret)
    {
      pelz_log(LOG_ERR, "%d::Error handling message", sockfd);
      while (!pelz_key_socket_check(sockfd))
      {
        continue;
      }
      pelz_key_socket_close(sockfd);
      return NULL;
    }
  }

  return NULL;
}


/* Function Description: Generates the response from the request message
 * Parameter Description:
 * [input] decrypted_data: pointer to decrypted data
 * [output] resp_buffer: pointer to response message, which is allocated in this function
 * [output] resp_length: this is response length
 * 
 * Note: This function would normally be protected in the enclave
 *       because the request message has already been decrypted,
 *       but the JSON library is currently only supported in unprotected code,
 *       so all unencrypted JSON fields must be exposed anyway.
 */
int ocall_handle_pelz_request_msg(char* req_data, size_t req_length, char** resp_buffer, size_t* resp_length)
{
  charbuf request;
  charbuf message;
  RequestResponseStatus status;
  const char *err_message;
  RequestType request_type = REQ_UNK;

  charbuf key_id;
  charbuf request_sig;
  charbuf requestor_cert;
  charbuf cipher_name;

  charbuf output = new_charbuf(0);
  charbuf input_data = new_charbuf(0);
  charbuf tag = new_charbuf(0);
  charbuf iv = new_charbuf(0);

  //Set placeholder results
  *resp_buffer = NULL;
  *resp_length = 0;

  //Place input data in a charbuf
  request = new_charbuf(0);
  request.chars = (unsigned char*) req_data;
  request.len = req_length;

  //Parse request for processing
  if (request_decoder(request, &request_type, &key_id, &cipher_name, &iv, &tag, &input_data, &request_sig, &requestor_cert))
  {
    err_message = "Missing Data";
    error_message_encoder(&message, err_message);
    *resp_buffer = (char *) message.chars;
    *resp_length = message.len;
    pelz_log(LOG_DEBUG, "Error: %.*s, %d", (int) message.len, message.chars, (int) message.len);
    return 0;
  }

  switch(request_type)
  {
  case REQ_ENC:
    pelz_encrypt_request_handler(eid, &status, request_type, key_id, cipher_name, input_data, &output, &iv, &tag, request_sig, requestor_cert);
    if (status == KEK_NOT_LOADED)
    {
      if (key_load(key_id) == 0)
      {
        pelz_encrypt_request_handler(eid, &status, request_type, key_id, cipher_name, input_data, &output, &iv, &tag, request_sig, requestor_cert);
      }
      else
      {
        status = KEK_LOAD_ERROR;
      }
    }
    break;
  case REQ_DEC:
    pelz_decrypt_request_handler(eid, &status, request_type, key_id, cipher_name, input_data, iv, tag, &output, request_sig, requestor_cert);
    if (status == KEK_NOT_LOADED)
    {
      if (key_load(key_id) == 0)
      {
        pelz_decrypt_request_handler(eid, &status, request_type, key_id, cipher_name, input_data, iv, tag, &output, request_sig, requestor_cert);
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

  if (status != REQUEST_OK)
  {
    pelz_log(LOG_ERR, "Service Error\nSend error message.");
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
    message_encoder(request_type, key_id, cipher_name, iv, tag, output, &message);
    pelz_log(LOG_DEBUG, "Message Encode Complete");
    pelz_log(LOG_DEBUG, "Message: %.*s, %d", (int) message.len, message.chars, (int) message.len);
  }
  free_charbuf(&key_id);
  free_charbuf(&output);
  free_charbuf(&iv);
  free_charbuf(&tag);
  free_charbuf(&cipher_name);

  pelz_log(LOG_DEBUG, "Message & Length: %.*s, %d", (int) message.len, message.chars, (int) message.len);

  *resp_buffer = (char *) message.chars;
  *resp_length = message.len;

  return 0;
}
