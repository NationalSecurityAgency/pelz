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

/* This application is a demonstration program for pelz.
 * It simulates a "worker" node by reading an encrypted data file
 * and a wrapped data encryption key (DEK) from the filesystem,
 * asking pelz to unwrap the key using a confidential key encryption key (KEK),
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

#define ENCLAVE_INITIATOR_NAME "bin/libenclave_initiator.signed.so"

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT "10601"
#define PELZ_REQ_ENC 1
#define PELZ_REQ_DEC 2
#define WRAP_CIPHER "AES/KeyWrap/RFC3394NoPadding/128"
#define MAX_RESP_LEN 1024
#define ENCRYPT_FORMAT "PELZ001\0"

static sgx_enclave_id_t initiator_enclave_id = 0;

typedef enum
{
    CMD_ENCRYPT,
    CMD_DECRYPT,
    CMD_SEARCH
} command_codes;

typedef struct __attribute__ ((__packed__)) encrypt_bundle {
  uint8_t format_code[8];
  uint8_t kek_id[128];
  uint8_t key[32];
  uint8_t iv[12];
  uint8_t tag[16];
  uint8_t cipher_data[];
} encrypt_bundle;

void print_usage(const char *prog)
{
    fprintf(stdout,
        "Usage: %s COMMAND ARGUMENTS ...\n"
        "\n"
        "Commands:\n"
        "  encrypt DATA_FILE OUT_FILE KEK_ID\n"
        "  decrypt DATA_FILE OUT_FILE\n"
        "  search DATA_FILE KEYWORD\n"  // placeholder
        , prog);
}

int parse_command(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Missing command line arguments.\n");
        print_usage(argv[0]);
        exit(-1);
    }

    char *command = argv[1];
    if (strcmp(command, "encrypt") == 0)
    {
        if (argc != 5)
        {
            printf("Invalid command line arguments.\n");
            print_usage(argv[0]);
            exit(-1);
        }
        return CMD_ENCRYPT;
    }
    else if (strcmp(command, "decrypt") == 0)
    {
        if (argc != 4)
        {
            printf("Invalid command line arguments.\n");
            print_usage(argv[0]);
            exit(-1);
        }
        return CMD_DECRYPT;
    }
    else if (strcmp(command, "search") == 0)
    {
        if (argc != 4)
        {
            printf("Invalid command line arguments.\n");
            print_usage(argv[0]);
            exit(-1);
        }
        return CMD_SEARCH;
    }
    else
    {
        printf("Invalid command line arguments.\n");
        print_usage(argv[0]);
        exit(-1);
    }
}

int create_pelz_request(int request_type, const char *kek_id, uint8_t *dek, size_t dek_len, char **request_msg)
{
    int ret;
    cJSON *request;
    char *encoded_dek;
    size_t encoded_dek_len;

    // TODO: 1. Change the message to a signed pelz request.
    // TODO: 2. Change the message to a signed pelz request with individually encrypted fields.
    // TODO: 3. Generate the request signature using a double-wrapped signing key (using kmyth).

    ret = encodeBase64Data(dek, dek_len, (uint8_t **) &encoded_dek, &encoded_dek_len);
    if (ret != 0)
    {
        printf("base-64 encoding failed\n");
        return -1;
    }

    request = cJSON_CreateObject();

    cJSON_AddItemToObject(request, "request_type", cJSON_CreateNumber(request_type));
    cJSON_AddItemToObject(request, "cipher", cJSON_CreateString(WRAP_CIPHER));
    cJSON_AddItemToObject(request, "key_id", cJSON_CreateString(kek_id));

    cJSON_AddItemToObject(request, "data", cJSON_CreateString(encoded_dek));
    free(encoded_dek);
    encoded_dek = NULL;

    *request_msg = cJSON_PrintUnformatted(request);

    cJSON_Delete(request);

    return 0;
}

int decode_response_data(char *json_str, uint8_t **data, size_t *len)
{
    cJSON *json = cJSON_Parse(json_str);
    if (json == NULL)
    {
        printf("cJSON_Parse error");
        return -1;
    }

    const char *field_name = "data";
    const cJSON *field = cJSON_GetObjectItemCaseSensitive(json, field_name);
    if (!cJSON_IsString(field) || field->valuestring == NULL)
    {
        printf("Missing JSON field: %s", field_name);
        cJSON_Delete(json);
        return -1;
    }

    if (decodeBase64Data((unsigned char *) field->valuestring, strlen(field->valuestring),
                         data, len))
    {
        printf("decodeBase64Data error");
        cJSON_Delete(json);
        return -1;
    }

    cJSON_Delete(json);
    return 0;
}

int encrypt_wrap_store(uint8_t *data, size_t data_len, const char *kek_id, char *out_path)
{
    uint32_t ret_status;
    sgx_status_t sgx_status;

    size_t bundle_len = sizeof(encrypt_bundle) + data_len;
    encrypt_bundle *bundle = (encrypt_bundle *) calloc(bundle_len, sizeof(uint8_t));
    if (bundle == NULL)
    {
        printf("allocation error\n");
        return -1;
    }

    if (strlen(kek_id) > sizeof(bundle->kek_id))
    {
        printf("kek id is too long\n");
        return -1;
    }

    sgx_status = demo_encrypt(initiator_enclave_id, &ret_status, data, data_len, (uint8_t *) &bundle, bundle_len);
    if (sgx_status != SGX_SUCCESS || ret_status != 0) {
        printf("encrypt_data Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", sgx_status, ret_status);
        free(bundle);
        return -1;
    }

    char *request;
    ret_status = create_pelz_request(PELZ_REQ_ENC, kek_id, bundle->key, sizeof(bundle->key), &request);
    if (ret_status != 0)
    {
        printf("request encoding failed\n");
        free(bundle);
        return -1;
    }

    printf("pelz request json: %s\n", request);

    char resp_buff[MAX_RESP_LEN] = { 0 };
    size_t resp_len = 0;

    sgx_status = sgx_make_pelz_request(initiator_enclave_id, &ret_status, request, strlen(request), MAX_RESP_LEN, resp_buff, &resp_len);
    free(request);
    request = NULL;

    if (sgx_status != SGX_SUCCESS || ret_status != 0) {
        printf("make_pelz_request Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", sgx_status, ret_status);
        free(bundle);
        return -1;
    }

    printf("pelz response json: %s\n", resp_buff);

    uint8_t *wrapped_dek;
    size_t wrapped_dek_len;
    if (decode_response_data(resp_buff, &wrapped_dek, &wrapped_dek_len))
    {
        free(bundle);
        return -1;
    }

    memcpy(bundle->key, wrapped_dek, sizeof(bundle->key));
    free(wrapped_dek);

    memcpy(bundle->format_code, ENCRYPT_FORMAT, sizeof(bundle->format_code));
    memcpy(bundle->kek_id, kek_id, strlen(kek_id));

    if (write_bytes_to_file(out_path, (uint8_t *) bundle, bundle_len))
    {
        printf("file write error\n");
        return -1;
    }

    free(bundle);

    return 0;
}

int unwrap_dek(uint8_t *bundle_data, size_t bundle_len)
{
    if (bundle_len < sizeof(encrypt_bundle))
    {
        printf("Invalid data file (size).");
        return -1;
    }

    encrypt_bundle *bundle = (encrypt_bundle *) bundle_data;
    if (strncmp((char *) bundle->format_code, ENCRYPT_FORMAT, sizeof(bundle->format_code)) != 0)
    {
        printf("Invalid data file (format code).");
        return -1;
    }

    int ret;
    char *request;
    ret = create_pelz_request(PELZ_REQ_DEC, (const char *) bundle->kek_id, bundle->key, sizeof(bundle->key), &request);
    if (ret != 0)
    {
        printf("request encoding failed\n");
        return -1;
    }

    printf("pelz request json: %s\n", request);

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

    printf("pelz response json: %s\n", resp_buff);

    uint8_t *dek;
    size_t dek_len;
    if (decode_response_data(resp_buff, &dek, &dek_len))
    {
        return -1;
    }
    memcpy(bundle->key, dek, sizeof(bundle->key));
    free(dek);

    return 0;
}

int unwrap_decrypt_store(uint8_t *bundle_data, size_t bundle_len, char *out_path)
{
    uint32_t ret_status;
    sgx_status_t sgx_status;

    if (unwrap_dek(bundle_data, bundle_len))
    {
        printf("pelz unwrapping failed\n");
        return -1;
    }

    size_t decrypt_data_len = bundle_len - sizeof(encrypt_bundle);
    uint8_t *decrypt_data = (uint8_t *) calloc(decrypt_data_len, sizeof(uint8_t));
    if (decrypt_data == NULL)
    {
        printf("allocation error\n");
        return -1;
    }

    sgx_status = demo_decrypt(initiator_enclave_id, &ret_status, bundle_data, bundle_len, decrypt_data, decrypt_data_len);
    if (sgx_status != SGX_SUCCESS || ret_status != 0) {
        printf("decrypt_data Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", sgx_status, ret_status);
        free(decrypt_data);
        return -1;
    }

    if (write_bytes_to_file(out_path, decrypt_data, decrypt_data_len))
    {
        printf("file write error\n");
        free(decrypt_data);
        return -1;
    }

    free(decrypt_data);

    return 0;
}

int unwrap_decrypt_search(uint8_t *bundle_data, size_t bundle_len, char *search_term)
{
    uint32_t ret_status;
    sgx_status_t sgx_status;

    if (unwrap_dek(bundle_data, bundle_len))
    {
        printf("pelz unwrapping failed\n");
        return -1;
    }

    int result_count;
    sgx_status = demo_decrypt_search(initiator_enclave_id, &ret_status, bundle_data, bundle_len, search_term, &result_count);
    if (sgx_status != SGX_SUCCESS || ret_status != 0) {
        printf("decrypt_search_data Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", sgx_status, ret_status);
        return -1;
    }

    printf("search for %s found %d occurrences\n", search_term, result_count);

    return 0;
}

int main(int argc, char* argv[])
{
    int command_code = parse_command(argc, argv);

    char *data_path = argv[2];

    uint8_t *data;
    size_t data_len;

    int update = 0;
    uint32_t ret_status;
    sgx_status_t status;
    sgx_launch_token_t token = {0};

    if (read_bytes_from_file(data_path, &data, &data_len)) {
        printf("failed to read the data file at %s.\n", data_path);
        return -1;
    }

    // Establish the socket connection that will be used to communicate with pelz
    if (connect_to_server(SERVER_ADDR, SERVER_PORT) == -1) {
        printf("failed to connect to the pelz server.\n");
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

    // execute command
    switch (command_code)
    {
    case CMD_ENCRYPT:
    {
        char *out_path = argv[3];
        char *kek_id = argv[4];
        if (encrypt_wrap_store(data, data_len, kek_id, out_path)) {
            printf("encrypt_wrap failed\n");
            sgx_destroy_enclave(initiator_enclave_id);
            return -1;
        }
        break;
    }
    case CMD_DECRYPT:
    {
        char *out_path = argv[3];
        if (unwrap_decrypt_store(data, data_len, out_path)) {
            printf("unwrap_decrypt failed\n");
            sgx_destroy_enclave(initiator_enclave_id);
            return -1;
        }
        break;
    }
    case CMD_SEARCH:
    {
        char *keyword = argv[3];
        if (unwrap_decrypt_search(data, data_len, keyword)) {
            printf("unwrap_decrypt_search failed\n");
            sgx_destroy_enclave(initiator_enclave_id);
            return -1;
        }
        break;
    }
    default:
        return -1;
        break;
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
