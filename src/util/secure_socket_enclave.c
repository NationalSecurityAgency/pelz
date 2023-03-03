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

//Process an incoming message and store data in the session object
ATTESTATION_STATUS handle_incoming_msg(secure_message_t *req_message,
                                       size_t req_message_size,
                                       uint32_t session_id)
{
    uint32_t plaintext_length;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    uint8_t l_tag[TAG_SIZE];
    size_t header_size, expected_payload_size;
    dh_session_t *session_info;
    sgx_status_t status;

    plaintext_length = 0;

    if(!req_message)
    {
        return INVALID_PARAMETER_ERROR;
    }

    //Retrieve the session information for the corresponding session id
    session_info = dh_sessions[session_id];
    if(session_info == NULL || session_info->status != ACTIVE)
    {
        return INVALID_SESSION;
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

    // Store plaintext in session object
    if(session_info->request_data != NULL) {
        SAFE_FREE(session_info->request_data);
    }

    session_info->request_data = (char *) decrypted_data;
    session_info->request_data_length = decrypted_data_length;

    return SUCCESS;
}

//Construct an outgoing message containing data stored in the session object
ATTESTATION_STATUS handle_outgoing_msg(size_t max_payload_size,
                                       secure_message_t **resp_message,
                                       size_t *resp_message_size,
                                       size_t resp_message_max_size,
                                       uint32_t session_id)
{
    char* resp_data;
    size_t resp_data_length;
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    size_t resp_message_calc_size;
    dh_session_t *session_info;
    secure_message_t* temp_resp_message;
    sgx_status_t status;

    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    //Retrieve the session information for the corresponding session id
    session_info = dh_sessions[session_id];
    if(session_info == NULL || session_info->status != ACTIVE || session_info->response_data == NULL)
    {
        return INVALID_SESSION;
    }

    resp_data = session_info->response_data;
    resp_data_length = session_info->response_data_length;

    if(resp_data_length > max_payload_size)
    {
        return OUT_BUFFER_LENGTH_ERROR;
    }

    resp_message_calc_size = sizeof(secure_message_t) + resp_data_length;

    if(resp_message_calc_size > resp_message_max_size)
    {
        return OUT_BUFFER_LENGTH_ERROR;
    }

    //Code to build the response back to the Source Enclave
    temp_resp_message = (secure_message_t*)malloc(resp_message_calc_size);
    if(!temp_resp_message)
    {
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
        SAFE_FREE(temp_resp_message);
        return status;
    }

    *resp_message_size = sizeof(secure_message_t) + resp_data_length;
    ocall_malloc(*resp_message_size, (unsigned char **) resp_message);
    memcpy(*resp_message, temp_resp_message, *resp_message_size);

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

ATTESTATION_STATUS get_request_data(uint32_t session_id, char **request_data, size_t *request_data_length)
{
    dh_session_t *session_info;

    //Retrieve the session information for the corresponding session id
    session_info = dh_sessions[session_id];
    if(session_info == NULL || session_info->status != ACTIVE || session_info->request_data == NULL)
    {
        return INVALID_SESSION;
    }

    *request_data_length = session_info->request_data_length;
    ocall_malloc(*request_data_length, (unsigned char **) request_data);
    memcpy(*request_data, session_info->request_data, *request_data_length);

    return SUCCESS;
}

ATTESTATION_STATUS save_response_data(uint32_t session_id, char *response_data, size_t response_data_length)
{
    dh_session_t *session_info;

    //Retrieve the session information for the corresponding session id
    session_info = dh_sessions[session_id];
    if(session_info == NULL || session_info->status != ACTIVE || session_info->request_data == NULL)
    {
        return INVALID_SESSION;
    }

    if(session_info->response_data != NULL) {
        SAFE_FREE(session_info->response_data);
    }

    session_info->response_data = malloc(response_data_length);
    if(!session_info->response_data)
    {
        return MALLOC_ERROR;
    }

    memcpy(session_info->response_data, response_data, response_data_length);
    session_info->response_data_length = response_data_length;

    return SUCCESS;
}
