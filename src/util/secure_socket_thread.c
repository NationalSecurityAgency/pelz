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

/* Function Description:
 *  This function responds to initiator enclave's connection request by generating and sending back ECDH message 1
 * Parameter Description:
 *  [input] clientfd: this is client's connection id. After generating ECDH message 1, server would send back response through this connection id.
 * */
int generate_and_send_session_msg1_resp(int clientfd)
{
  int retcode = 0;
  uint32_t status = 0;
  sgx_status_t ret = SGX_SUCCESS;
  SESSION_MSG1_RESP msg1resp;
  FIFO_MSG * fifo_resp = NULL;
  size_t respmsgsize;

  memset(&msg1resp, 0, sizeof(SESSION_MSG1_RESP));

  // call responder enclave to generate ECDH message 1
  ret = session_request(e2_enclave_id, &status, &msg1resp.dh_msg1, &msg1resp.sessionid);
  if (ret != SGX_SUCCESS)
  {
    printf("failed to do ECALL session_request.\n");
    return -1;
  }

  respmsgsize = sizeof(FIFO_MSG) + sizeof(SESSION_MSG1_RESP);
  fifo_resp = (FIFO_MSG *)malloc(respmsgsize);
  if (!fifo_resp)
  {
    printf("memory allocation failure.\n");
    return -1;
  }
  memset(fifo_resp, 0, respmsgsize);

  fifo_resp->header.type = FIFO_DH_RESP_MSG1;
  fifo_resp->header.size = sizeof(SESSION_MSG1_RESP);

  memcpy(fifo_resp->msgbuf, &msg1resp, sizeof(SESSION_MSG1_RESP));

  //send message 1 to client
  if (send(clientfd, reinterpret_cast<char *>(fifo_resp), static_cast<int>(respmsgsize), 0) == -1)
  {
    printf("fail to send msg1 response.\n");
    retcode = -1;
  }
  free(fifo_resp);
  return retcode;
}

/* Function Description:
 *  This function process ECDH message 2 received from client and send message 3 to client
 * Parameter Description:
 *  [input] clientfd: this is client's connection id
 *  [input] msg2: this contains ECDH message 2 received from client
 * */
int process_exchange_report(int clientfd, SESSION_MSG2 * msg2)
{
  uint32_t status = 0;
  sgx_status_t ret = SGX_SUCCESS;
  FIFO_MSG *response;
  SESSION_MSG3 * msg3;
  size_t msgsize;

  if (!msg2)
    return -1;

  msgsize = sizeof(FIFO_MSG_HEADER) + sizeof(SESSION_MSG3);
  response = (FIFO_MSG *)malloc(msgsize);
  if (!response)
  {
    printf("memory allocation failure\n");
    return -1;
  }
  memset(response, 0, msgsize);

  response->header.type = FIFO_DH_MSG3;
  response->header.size = sizeof(SESSION_MSG3);

  msg3 = (SESSION_MSG3 *)response->msgbuf;
  msg3->sessionid = msg2->sessionid;

  // call responder enclave to process ECDH message 2 and generate message 3
  ret = exchange_report(e2_enclave_id, &status, &msg2->dh_msg2, &msg3->dh_msg3, msg2->sessionid);
  if (ret != SGX_SUCCESS)
  {
    printf("EnclaveResponse_exchange_report failure.\n");
    free(response);
    return -1;
  }

  // send ECDH message 3 to client
  if (send(clientfd, reinterpret_cast<char *>(response), static_cast<int>(msgsize), 0) == -1)
  {
    printf("server_send() failure.\n");
    free(response);
    return -1;
  }

  free(response);

  return 0;
}

/* Function Description:
 *  This function process received message communication from client
 * Parameter Description:
 *  [input] clientfd: this is client's connection id
 *  [input] req_msg: this is pointer to received message from client
 * */
int process_msg_transfer(int clientfd, FIFO_MSGBODY_REQ *req_msg)
{
  uint32_t status = 0;
  sgx_status_t ret = SGX_SUCCESS;
  secure_message_t *resp_message = NULL;
  FIFO_MSG * fifo_resp = NULL;
  size_t resp_message_size;

  if (!req_msg)
  {
    printf("invalid parameter.\n");
    return -1;
  }

  resp_message_size = sizeof(secure_message_t) + req_msg->max_payload_size;
  //Allocate memory for the response message
  resp_message = (secure_message_t*)malloc(resp_message_size);
  if (!resp_message)
  {
    printf("memory allocation failure.\n");
    return -1;
  }
  memset(resp_message, 0, resp_message_size);

  ret = generate_response(e2_enclave_id, &status, (secure_message_t *)req_msg->buf, req_msg->size, req_msg->max_payload_size, resp_message, resp_message_size, req_msg->session_id);
  if (ret != SGX_SUCCESS)
  {
    printf("EnclaveResponder_generate_response error.\n");
    free(resp_message);
    return -1;
  }

  fifo_resp = (FIFO_MSG *)malloc(sizeof(FIFO_MSG) + resp_message_size);
  if (!fifo_resp)
  {
    printf("memory allocation failure.\n");
    free(resp_message);
    return -1;
  }
  memset(fifo_resp, 0, sizeof(FIFO_MSG) + resp_message_size);

  fifo_resp->header.type = FIFO_DH_MSG_RESP;
  fifo_resp->header.size = resp_message_size;
  memcpy(fifo_resp->msgbuf, resp_message, resp_message_size);

  free(resp_message);

  if (send(clientfd, reinterpret_cast<char *>(fifo_resp), sizeof(FIFO_MSG) + static_cast<int>(resp_message_size), 0) == -1)
  {
    printf("server_send() failure.\n");
    free(fifo_resp);
    return -1;
  }
  free(fifo_resp);

  return 0;
}

/* Function Description: This is process session close request from client
 * Parameter Description:
 *  [input] clientfd: this is client connection id
 *  [input] close_req: this is pointer to client's session close request
 * */
int process_close_req(int clientfd, SESSION_CLOSE_REQ * close_req)
{
  uint32_t status = 0;
  sgx_status_t ret = SGX_SUCCESS;
  FIFO_MSG close_ack;

  if (!close_req)
    return -1;

  // call responder enclave to close this session
  ret = end_session(e2_enclave_id, &status, close_req->session_id);
  if (ret != SGX_SUCCESS)
    return -1;

  // send back response
  close_ack.header.type = FIFO_DH_CLOSE_RESP;
  close_ack.header.size = 0;

  if (send(clientfd, reinterpret_cast<char *>(&close_ack), sizeof(FIFO_MSG), 0) == -1)
  {
    printf("server_send() failure.\n");
    return -1;
  }

  return 0;
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

  // TODO: Do ECDH handshake to establish session

  // init session metadata (if necessary)
  // (keep track of session ID)

  // recv request
  // gen msg1 (ecall)
  // send msg1

  // recv msg2
  // gen msg3 (ecall)
  // sed msg3

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

    switch (message->header.type)
    {
      case FIFO_DH_REQ_MSG1:
      {
        // process ECDH session connection request
        if (generate_and_send_session_msg1_resp(sockfd) != 0)
        {
          printf("failed to generate and send session msg1 resp.\n");
          break;
        }
      }
      break;

      case FIFO_DH_MSG2:
      {
        // process ECDH message 2
        if (process_exchange_report(sockfd, (SESSION_MSG2 *) message->msgbuf) != 0)
        {
          printf("failed to process exchange_report request.\n");
          break;
        }
      }
      break;

      case FIFO_DH_MSG_REQ:
      {
        // process message transfer request
        if (process_msg_transfer(sockfd, (FIFO_MSGBODY_REQ *) message->msgbuf) != 0)
        {
          printf("failed to process message transfer request.\n");
          break;
        }
      }
      break;

      case FIFO_DH_CLOSE_REQ:
      {
        // process message close request
        process_close_req(sockfd, (SESSION_CLOSE_REQ *) message->msgbuf);
      }
      break;

      default:
      {
        printf("Unknown message.\n");
      }
      break;
    }

    free(message);
    message = NULL;
  }
}

int handle_pelz_request(charbuf request)
{
    // TODO
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
