/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* Note: This code is adapted from linux-sgx/SampleCode/LocalAttestation/AppResponder/CPTask.cpp */

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
  ret = session_request(eid, &status, &msg1resp.dh_msg1, &msg1resp.sessionid);
  if (ret != SGX_SUCCESS)
  {
    pelz_log(LOG_ERR, "failed to do ECALL session_request.\n");
    return -1;
  }

  respmsgsize = sizeof(FIFO_MSG) + sizeof(SESSION_MSG1_RESP);
  fifo_resp = (FIFO_MSG *)malloc(respmsgsize);
  if (!fifo_resp)
  {
    pelz_log(LOG_ERR, "memory allocation failure.\n");
    return -1;
  }
  memset(fifo_resp, 0, respmsgsize);

  fifo_resp->header.type = FIFO_DH_RESP_MSG1;
  fifo_resp->header.size = sizeof(SESSION_MSG1_RESP);

  memcpy(fifo_resp->msgbuf, &msg1resp, sizeof(SESSION_MSG1_RESP));

  //send message 1 to client
  if (send(clientfd, reinterpret_cast<char *>(fifo_resp), static_cast<int>(respmsgsize), 0) == -1)
  {
    pelz_log(LOG_ERR, "fail to send msg1 response.\n");
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
    pelz_log(LOG_ERR, "memory allocation failure\n");
    return -1;
  }
  memset(response, 0, msgsize);

  response->header.type = FIFO_DH_MSG3;
  response->header.size = sizeof(SESSION_MSG3);

  msg3 = (SESSION_MSG3 *)response->msgbuf;
  msg3->sessionid = msg2->sessionid;

  // call responder enclave to process ECDH message 2 and generate message 3
  ret = exchange_report(eid, &status, &msg2->dh_msg2, &msg3->dh_msg3, msg2->sessionid);
  if (ret != SGX_SUCCESS)
  {
    pelz_log(LOG_ERR, "EnclaveResponse_exchange_report failure.\n");
    free(response);
    return -1;
  }

  // send ECDH message 3 to client
  if (send(clientfd, reinterpret_cast<char *>(response), static_cast<int>(msgsize), 0) == -1)
  {
    pelz_log(LOG_ERR, "server_send() failure.\n");
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
    pelz_log(LOG_ERR, "invalid parameter.\n");
    return -1;
  }

  resp_message_size = sizeof(secure_message_t) + req_msg->max_payload_size;
  //Allocate memory for the response message
  resp_message = (secure_message_t*)malloc(resp_message_size);
  if (!resp_message)
  {
    pelz_log(LOG_ERR, "memory allocation failure.\n");
    return -1;
  }
  memset(resp_message, 0, resp_message_size);

  ret = generate_response(eid, &status, (secure_message_t *)req_msg->buf, req_msg->size, req_msg->max_payload_size, resp_message, resp_message_size, req_msg->session_id);
  if (ret != SGX_SUCCESS)
  {
    pelz_log(LOG_ERR, "EnclaveResponder_generate_response error.\n");
    free(resp_message);
    return -1;
  }

  fifo_resp = (FIFO_MSG *)malloc(sizeof(FIFO_MSG) + resp_message_size);
  if (!fifo_resp)
  {
    pelz_log(LOG_ERR, "memory allocation failure.\n");
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
    pelz_log(LOG_ERR, "server_send() failure.\n");
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
  ret = end_session(eid, &status, close_req->session_id);
  if (ret != SGX_SUCCESS)
    return -1;

  // send back response
  close_ack.header.type = FIFO_DH_CLOSE_RESP;
  close_ack.header.size = 0;

  if (send(clientfd, reinterpret_cast<char *>(&close_ack), sizeof(FIFO_MSG), 0) == -1)
  {
    pelz_log(LOG_ERR, "server_send() failure.\n");
    return -1;
  }

  return 0;
}

int handle_message(int sockfd, FIFO_MSG * message)
{
  switch (message->header.type)
  {
    case FIFO_DH_REQ_MSG1:
    {
      // process ECDH session connection request
      if (generate_and_send_session_msg1_resp(sockfd) != 0)
      {
        pelz_log(LOG_ERR, "failed to generate and send session msg1 resp.\n");
        return -1;
      }
    }
    break;

    case FIFO_DH_MSG2:
    {
      // process ECDH message 2
      if (process_exchange_report(sockfd, (SESSION_MSG2 *) message->msgbuf) != 0)
      {
        pelz_log(LOG_ERR, "failed to process exchange_report request.\n");
        return -1;
      }
    }
    break;

    case FIFO_DH_MSG_REQ:
    {
      // process message transfer request
      if (process_msg_transfer(sockfd, (FIFO_MSGBODY_REQ *) message->msgbuf) != 0)
      {
        pelz_log(LOG_ERR, "failed to process message transfer request.\n");
        return -1;
      }
    }
    break;

    case FIFO_DH_CLOSE_REQ:
    {
      // process message close request
      if (process_close_req(sockfd, (SESSION_CLOSE_REQ *) message->msgbuf) != 0)
      {
        pelz_log(LOG_ERR, "failed to close ecdh session.\n");
        return -1;
      }
    }
    break;

    default:
    {
      pelz_log(LOG_ERR, "Unknown message.\n");
    }
    break;
  }

  return 0;
}



