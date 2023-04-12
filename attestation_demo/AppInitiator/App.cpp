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

/* This application is a demonstration program for Pelz.
 * It simulates a "worker" node by reading an encrypted data file
 * and a wrapped data encryption key (DEK) from the filesystem,
 * asking Pelz to unwrap the key using a confidential key encryption key (KEK),
 * then decrypting the data file and using the data.
 */

#include <stdio.h>
#include <map>
#include <sched.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include <kmyth/file_io.h>
#include <kmyth/formatting_tools.h>

#include "sgx_eid.h"
#include "sgx_urts.h"

#include "EnclaveInitiator_u.h"

#include "fifo_def.h"

#define ENCLAVE_INITIATOR_NAME "libenclave_initiator.signed.so"

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT "10601"
#define PELZ_REQ_DEC 2
#define PELZ_CIPHER "AES/KeyWrap/RFC3394NoPadding/128"
#define KEY_ID_PREFIX "file:"
#define MAX_RESP_LEN 1024

static sgx_enclave_id_t initiator_enclave_id = 0;


int create_pelz_request(const char *kek_path, uint8_t *wrapped_dek, size_t wrapped_dek_len, char **request_msg)
{
    int ret;
    cJSON *request;
    char *wrapped_encoded_dek;
    size_t wrapped_encoded_dek_len;
    char *kek_id;

    ret = encodeBase64Data(wrapped_dek, wrapped_dek_len, (uint8_t **) &wrapped_encoded_dek, &wrapped_encoded_dek_len);
    if (ret != 0)
    {
        printf("base-64 encoding failed\n");
        return -1;
    }

    request = cJSON_CreateObject();

    cJSON_AddItemToObject(request, "request_type", cJSON_CreateNumber(PELZ_REQ_DEC));
    cJSON_AddItemToObject(request, "cipher", cJSON_CreateString(PELZ_CIPHER));

    cJSON_AddItemToObject(request, "data", cJSON_CreateString(wrapped_encoded_dek));
    free(wrapped_encoded_dek);
    wrapped_encoded_dek = NULL;

    kek_id = (char *) calloc(strlen(KEY_ID_PREFIX) + strlen(kek_path) + 1, sizeof(char));
    if (kek_id == NULL)
    {
        printf("allocation failure\n");
        cJSON_Delete(request);
        return -1;
    }

    sprintf(kek_id, "%s%s", KEY_ID_PREFIX, kek_path);
    cJSON_AddItemToObject(request, "key_id", cJSON_CreateString(kek_id));

    free(kek_id);
    kek_id = NULL;

    *request_msg = cJSON_PrintUnformatted(request);

    cJSON_Delete(request);

    return 0;
}

int unwrap_and_decrypt(const char *kek_path, uint8_t *wrapped_dek, size_t wrapped_dek_len)
{
    int ret;
    char *request;

    // TODO: 1. Change the message to a signed pelz request.
    // TODO: 2. Change the message to a signed pelz request with individually encrypted fields.
    // TODO: 3. Generate the request signature using a double-wrapped signing key (using kmyth).

    ret = create_pelz_request(kek_path, wrapped_dek, wrapped_dek_len, &request);
    if (ret != 0)
    {
        printf("request encoding failed\n");
        return -1;
    }

    printf("Pelz request json: %s\n", request);

    char resp_buff[MAX_RESP_LEN] = { 0 };
    size_t resp_len = 0;
    uint32_t ret_status = 0;
    sgx_status_t sgx_status;

    sgx_status = sgx_make_pelz_request(initiator_enclave_id, &ret_status, request, strlen(request), MAX_RESP_LEN, resp_buff, &resp_len);
    free(request);
    request = NULL;

    if (sgx_status != SGX_SUCCESS || ret_status != 0) {
        printf("make_pelz_request Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", sgx_status, ret_status);
        return -1;
    }

    printf("pelz response %s, %zu\n", resp_buff, resp_len);

    // TODO: decode request
    // TODO: decrypt data
    // TODO: do something with data

    return 0;
}


int main(int argc, char* argv[])
{
    int update = 0;
    uint32_t ret_status;
    sgx_status_t status;
    sgx_launch_token_t token = {0};

    if (argc != 4) {
        printf("Missing command line arguments.\n");
        printf("Usage: %s DATA_FILE DEK_FILE KEK_ID\n", argv[0]);
        return -1;
    }

    char *data_path = argv[1];
    char *dek_path = argv[2];
    char *kek_id = argv[3];

    uint8_t *data;
    size_t data_len;
    uint8_t *wrapped_dek;
    size_t wrapped_dek_len;

    if (read_bytes_from_file(data_path, &data, &data_len)) {
        printf("failed to read the data file at %s.\n", data_path);
        return -1;
    }

    if (read_bytes_from_file(dek_path, &wrapped_dek, &wrapped_dek_len)) {
        printf("failed to read the dek file at %s.\n", data_path);
        return -1;
    }

    // Establish the socket connection that will be used to communicate with Pelz
    if (connect_to_server(SERVER_ADDR, SERVER_PORT) == -1) {
        printf("failed to connect to the Pelz server.\n");
        return -1;
    }

    // create ECDH initiator enclave
    status = sgx_create_enclave(ENCLAVE_INITIATOR_NAME, SGX_DEBUG_FLAG, &token, &update, &initiator_enclave_id, NULL);
    if (status != SGX_SUCCESS) {
        printf("failed to load enclave %s, error code is 0x%x.\n", ENCLAVE_INITIATOR_NAME, status);
        return -1;
    }
    printf("succeed to load enclave %s\n", ENCLAVE_INITIATOR_NAME);

    // establish an ECDH session with the responder enclave running in another process
    status = test_create_session(initiator_enclave_id, &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
        printf("failed to establish secure channel: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        sgx_destroy_enclave(initiator_enclave_id);
        return -1;
    }
    printf("succeed to establish secure channel.\n");

    // do work
    if (unwrap_and_decrypt(kek_id, wrapped_dek, wrapped_dek_len)) {
        printf("unwrap_and_decrypt failed\n");
        sgx_destroy_enclave(initiator_enclave_id);
        return -1;
    }

    // close ECDH session
    status = test_close_session(initiator_enclave_id, &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
        printf("test_close_session Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        sgx_destroy_enclave(initiator_enclave_id);
        return -1;
    }
    printf("Succeed to close Session...\n");

    sgx_destroy_enclave(initiator_enclave_id);

    return 0;
}
