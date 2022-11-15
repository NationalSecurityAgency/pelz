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

/* Note: much of this code is adapted from linux-sgx/SampleCode/LocalAttestation/EnclaveResponder/EnclaveMessageExchange.cpp */

#include <string.h>

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"

#include "charbuf.h"
#include "dh_error_codes.h"
#include "pelz_request_handler.h"
#include "secure_socket_ecdh.h"
#include "pelz_json_parser.h"
#include "pelz_enclave_log.h"

#include ENCLAVE_HEADER_TRUSTED


#define MAX_SESSION_COUNT  16

//Array of pointers to session info
dh_session_t *dh_sessions[MAX_SESSION_COUNT] = { 0 };

ATTESTATION_STATUS generate_session_id(uint32_t *session_id);
uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity);
int handle_pelz_request_msg(char* req_data, size_t req_length, char** resp_buffer, size_t* resp_length);


//Handle the request from Source Enclave for a session
ATTESTATION_STATUS session_request(sgx_dh_msg1_t *dh_msg1,
                          uint32_t *session_id )
{
    dh_session_t *session_info;
    sgx_dh_session_t sgx_dh_session;
    sgx_status_t status = SGX_SUCCESS;

    if(!session_id || !dh_msg1)
    {
        return INVALID_PARAMETER_ERROR;
    }
    //Intialize the session as a session responder
    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        return status;
    }

    //get a new SessionID
    if ((status = (sgx_status_t)generate_session_id(session_id)) != SUCCESS)
        return status; //no more sessions available

    //Allocate session info and store in the tracker
    session_info = (dh_session_t *)calloc(1, sizeof(dh_session_t));
    if(!session_info)
    {
        return MALLOC_ERROR;
    }

    // memset(session_info, 0, sizeof(dh_session_t));
    session_info->session_id = *session_id;
    session_info->status = IN_PROGRESS;

    //Generate Message1 that will be returned to Source Enclave
    status = sgx_dh_responder_gen_msg1((sgx_dh_msg1_t*)dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(session_info);
        return status;
    }
    memcpy(&session_info->in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));
    dh_sessions[*session_id] = session_info;

    return status;
}

//Verify Message 2, generate Message3 and exchange Message 3 with Source Enclave
ATTESTATION_STATUS exchange_report(sgx_dh_msg2_t *dh_msg2,
                          sgx_dh_msg3_t *dh_msg3,
                          uint32_t session_id)
{

    sgx_key_128bit_t dh_aek;   // Session key
    dh_session_t *session_info;
    ATTESTATION_STATUS status = SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t initiator_identity;

    if(!dh_msg2 || !dh_msg3)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    do
    {
        //Retrieve the session information for the corresponding session id
        session_info = dh_sessions[session_id];

        if(session_info == NULL || session_info->status != IN_PROGRESS)
        {
            status = INVALID_SESSION;
            break;
        }

        memcpy(&sgx_dh_session, &session_info->in_progress.dh_session, sizeof(sgx_dh_session_t));

        dh_msg3->msg3_body.additional_prop_length = 0;
        //Process message 2 from source enclave and obtain message 3
        sgx_status_t se_ret = sgx_dh_responder_proc_msg2(dh_msg2,
                                                       dh_msg3,
                                                       &sgx_dh_session,
                                                       &dh_aek,
                                                       &initiator_identity);
        if(SGX_SUCCESS != se_ret)
        {
            status = se_ret;
            break;
        }

        //Verify source enclave's trust
        if(verify_peer_enclave_trust(&initiator_identity) != SUCCESS)
        {
            return INVALID_SESSION;
        }

        //save the session ID, status and initialize the session nonce
        session_info->session_id = session_id;
        session_info->status = ACTIVE;
        session_info->active.counter = 0;
        memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
        memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    }while(0);

    if(status != SUCCESS)
    {
        end_session(session_id);
    }

    return status;
}

//Process the request from the Source enclave and send the response message back to the Source enclave
ATTESTATION_STATUS generate_response(secure_message_t* req_message,
                                     size_t req_message_size,
                                     size_t max_payload_size,
                                     secure_message_t* resp_message,
                                     size_t *resp_message_size,
                                     size_t resp_message_max_size,
                                     uint32_t session_id)
{
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    size_t resp_data_length;
    size_t resp_message_calc_size;
    char* resp_data;
    uint8_t l_tag[TAG_SIZE];
    size_t header_size, expected_payload_size;
    dh_session_t *session_info;
    secure_message_t* temp_resp_message;
    int ret;
    sgx_status_t status;

    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    if(!req_message || !resp_message)
    {
        return INVALID_PARAMETER_ERROR;
    }

    //Retrieve the session information for the corresponding session id
    session_info = dh_sessions[session_id];

    if(session_info == NULL || session_info->status != ACTIVE)
    {
        status = INVALID_SESSION;
    }

    //Set the decrypted data length to the payload size obtained from the message
    decrypted_data_length = req_message->message_aes_gcm_data.payload_size;

    header_size = sizeof(secure_message_t);
    expected_payload_size = req_message_size - header_size;

    //Verify the size of the payload
    if(expected_payload_size != decrypted_data_length)
        return INVALID_PARAMETER_ERROR;

    memset(&l_tag, 0, 16);
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    if(!decrypted_data)
    {
        return MALLOC_ERROR;
    }

    memset(decrypted_data, 0, decrypted_data_length);

    //Decrypt the request message payload from source enclave
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, req_message->message_aes_gcm_data.payload,
                decrypted_data_length, decrypted_data,
                (uint8_t *)(&(req_message->message_aes_gcm_data.reserved)),
                sizeof(req_message->message_aes_gcm_data.reserved), &(req_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length,
                &req_message->message_aes_gcm_data.payload_tag);

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(decrypted_data);
        return status;
    }

    // Verify if the nonce obtained in the request is equal to the session nonce
    if(*((uint32_t*)req_message->message_aes_gcm_data.reserved) != session_info->active.counter || *((uint32_t*)req_message->message_aes_gcm_data.reserved) > ((uint32_t)-2))
    {
        SAFE_FREE(decrypted_data);
        return INVALID_PARAMETER_ERROR;
    }

    // Call Pelz request message handler
    ret = handle_pelz_request_msg((char*)decrypted_data, decrypted_data_length, &resp_data, &resp_data_length);
    SAFE_FREE(decrypted_data);
    if(ret)
    {
        return ERROR_UNEXPECTED;
    }

    if(resp_data_length > max_payload_size)
    {
        ocall_free(resp_data, resp_data_length);
        return OUT_BUFFER_LENGTH_ERROR;
    }

    resp_message_calc_size = sizeof(secure_message_t) + resp_data_length;

    if(resp_message_calc_size > resp_message_max_size)
    {
        ocall_free(resp_data, resp_data_length);
        return OUT_BUFFER_LENGTH_ERROR;
    }

    //Code to build the response back to the Source Enclave
    temp_resp_message = (secure_message_t*)malloc(resp_message_calc_size);
    if(!temp_resp_message)
    {
        ocall_free(resp_data, resp_data_length);
        return MALLOC_ERROR;
    }

    memset(temp_resp_message,0,sizeof(secure_message_t)+ resp_data_length);
    const uint32_t data2encrypt_length = (uint32_t)resp_data_length;
    temp_resp_message->session_id = session_info->session_id;
    temp_resp_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    //Increment the Session Nonce (Replay Protection)
    session_info->active.counter = session_info->active.counter + 1;

    //Set the response nonce as the session nonce
    memcpy(&temp_resp_message->message_aes_gcm_data.reserved,&session_info->active.counter,sizeof(session_info->active.counter));

    //Prepare the response message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t*)resp_data, data2encrypt_length,
                (uint8_t *)(&(temp_resp_message->message_aes_gcm_data.payload)),
                (uint8_t *)(&(temp_resp_message->message_aes_gcm_data.reserved)),
                sizeof(temp_resp_message->message_aes_gcm_data.reserved), plaintext, plaintext_length,
                &(temp_resp_message->message_aes_gcm_data.payload_tag));

    if(SGX_SUCCESS != status)
    {
        ocall_free(resp_data, resp_data_length);
        SAFE_FREE(temp_resp_message);
        return status;
    }

    *resp_message_size = sizeof(secure_message_t) + resp_data_length;
    memset(resp_message, 0, resp_message_max_size);
    memcpy(resp_message, temp_resp_message, *resp_message_size);

    ocall_free(resp_data, resp_data_length);
    SAFE_FREE(temp_resp_message);

    return SUCCESS;
}


//Respond to the request from the Source Enclave to close the session
ATTESTATION_STATUS end_session(uint32_t session_id)
{
    ATTESTATION_STATUS status = SUCCESS;
    dh_session_t *session_info;

    //Retrieve the session information for the corresponding session id
    session_info = dh_sessions[session_id];

    if(session_info == NULL)
    {
        status = INVALID_SESSION;
    }

    //Erase the session information for the current session
    dh_sessions[session_id] = NULL;
    memset(session_info, 0, sizeof(dh_session_t));
    SAFE_FREE(session_info);

    return status;
}


//Returns a new sessionID for the source destination session
ATTESTATION_STATUS generate_session_id(uint32_t *session_id)
{
    ATTESTATION_STATUS status = SUCCESS;

    if(!session_id)
    {
        return INVALID_PARAMETER_ERROR;
    }

    // find the first unused entry in the session info array, and use the index as the session id
    for (int i = 0; i < MAX_SESSION_COUNT; i++)
    {
        if (dh_sessions[i] == NULL)
        {
            *session_id = i;
            return status;
        }
    }

    status = NO_AVAILABLE_SESSION_ERROR;

    return status;
}

/* Function Description:
 *   this is to verify peer enclave's identity
 * For demonstration purpose, we verify below points:
 *   1. peer enclave's MRSIGNER is as expected
 *   2. peer enclave's PROD_ID is as expected
 *   3. peer enclave's attribute is reasonable that it should be INITIALIZED and without DEBUG attribute (except the project is built with DEBUG option)
 * */
uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if(!peer_enclave_identity)
        return INVALID_PARAMETER_ERROR;

    // TODO: possibly compare peer enclave's MRSIGNER to known value
    // if (memcmp((uint8_t *)&peer_enclave_identity->mr_signer, (uint8_t*)&g_initiator_mrsigner, sizeof(sgx_measurement_t)))
    //     return ENCLAVE_TRUST_ERROR;

    if(peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        return ENCLAVE_TRUST_ERROR;

    // check the enclave isn't loaded in enclave debug mode, except that the project is built for debug purpose
#if defined(NDEBUG)
    if (peer_enclave_identity->attributes.flags & SGX_FLAGS_DEBUG)
        return ENCLAVE_TRUST_ERROR;
#endif

    return SUCCESS;
}

charbuf get_error_response(const char *err_message)
{
  int ret_ocall, ret_val;
  charbuf message;

  ret_ocall = ocall_encode_error(&ret_val, &message, err_message);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    message = new_charbuf(0);
  }
  return message;
}

/* Function Description: Generates the response from the request message
 * Parameter Description:
 * [input] req_data: pointer to decrypted request message
 * [input] req_length: request length
 * [output] resp_buffer: pointer to response message, which is allocated in this function
 * [output] resp_length: response length
 *
 * Note: The decode/encode ocalls are required because the JSON library
 *       is currently only supported in unprotected code,
 */
int handle_pelz_request_msg(char* req_data, size_t req_length, char** resp_buffer, size_t* resp_length)
{
  int ret_ocall, ret_val;
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

  //Parse request for processing
  ret_ocall = ocall_decode_request(&ret_val, req_data, req_length, &request_type, &key_id, &cipher_name, &iv, &tag, &input_data, &request_sig, &requestor_cert);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    err_message = "Missing Data";
    message = get_error_response(err_message);
    *resp_buffer = (char *) message.chars;
    *resp_length = message.len;
    return 0;
  }

  switch(request_type)
  {
  case REQ_ENC:
    status = pelz_encrypt_request_handler(request_type, key_id, cipher_name, input_data, &output, &iv, &tag, request_sig, requestor_cert);
    if (status == KEK_NOT_LOADED)
    {
      ret_ocall = ocall_key_load(&ret_val, key_id);
      if (ret_ocall == SGX_SUCCESS && ret_val == EXIT_SUCCESS)
      {
        status = pelz_encrypt_request_handler(request_type, key_id, cipher_name, input_data, &output, &iv, &tag, request_sig, requestor_cert);
      }
      else
      {
        status = KEK_LOAD_ERROR;
      }
    }
    break;
  case REQ_DEC:
    status = pelz_decrypt_request_handler(request_type, key_id, cipher_name, input_data, iv, tag, &output, request_sig, requestor_cert);
    if (status == KEK_NOT_LOADED)
    {
      ret_ocall = ocall_key_load(&ret_val, key_id);
      if (ret_ocall == SGX_SUCCESS && ret_val == EXIT_SUCCESS)
      {
        status = pelz_decrypt_request_handler(request_type, key_id, cipher_name, input_data, iv, tag, &output, request_sig, requestor_cert);
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
    message = get_error_response(err_message);
  }
  else
  {
    ret_ocall = ocall_encode_response(&ret_val, request_type, key_id, cipher_name, iv, tag, output, &message);
    if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
    {
      message = get_error_response("Encode Error");
    }
  }

  ocall_free(key_id.chars, key_id.len);
  ocall_free(output.chars, output.len);
  ocall_free(iv.chars, iv.len);
  ocall_free(tag.chars, tag.len);
  ocall_free(cipher_name.chars, tag.len);

  *resp_buffer = (char *) message.chars;
  *resp_length = message.len;

  // Return 1 if the response is empty, which can happen if an ocall fails.
  ret_val = *resp_length == 0;

  return ret_val;
}
