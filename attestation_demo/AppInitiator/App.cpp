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
#include <getopt.h>
#include <map>
#include <sched.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include <openssl/evp.h>
#include <kmyth/file_io.h>
#include <kmyth/formatting_tools.h>

#include "sgx_eid.h"
#include "sgx_urts.h"

#include "EnclaveInitiator_u.h"

#include "fifo_def.h"
#include "encrypt_datatypes.h"

#define ENCLAVE_INITIATOR_NAME "bin/libenclave_initiator.signed.so"

#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT "10601"
#define PELZ_REQ_ENC_SIGNED 3
#define PELZ_REQ_DEC_SIGNED 4
#define WRAP_CIPHER "AES/KeyWrap/RFC3394NoPadding/128"
#define MAX_RESP_LEN 1024
#define ENCRYPT_FORMAT "PELZ001\0"

static sgx_enclave_id_t initiator_enclave_id = 0;

void print_usage(const char *prog)
{
    fprintf(stdout,
        "Usage: %s COMMAND ARGUMENTS ...\n"
        "\n"
        "Commands:\n"
        "  encrypt KEK_ID\n"
        "  decrypt\n"
        "  search KEYWORD\n"
        "Options:\n"
        "-i DATA_FILE, --input-file=DATA_FILE   (required for all commands)\n"
        "-o OUT_FILE, --output-file=OUT_FILE    (required for encrypt and decrypt commands)\n"
        "-r PRIV_KEY, --signing-key=PRIV_KEY    (required for all commands, PEM format)\n"
        "-u PUB_KEY, --signing-cert=PUB_KEY     (required for all commands, PEM X509 format)\n"
        "-h, --help\n"
        , prog);
}

int serialize_request(uint64_t request_type, const char *kek_id, uint8_t *dek, size_t dek_len, uint8_t *cert, size_t cert_len, uint8_t **serial, size_t *serial_len)
{
    // IMPORTANT: serialized fields are not base-64 encoded, so better not to use the request json
    uint64_t kek_id_len = (uint64_t) strlen(kek_id);
    uint64_t cipher_len = (uint64_t) strlen(WRAP_CIPHER);
    uint64_t iv_len = 0;
    uint64_t tag_len = 0;
    uint64_t total_size = sizeof(uint64_t) * 6 + kek_id_len + cipher_len + dek_len + cert_len;

    if (request_type == PELZ_REQ_DEC_SIGNED)
    {
        total_size += sizeof(uint64_t) * 2 + iv_len + tag_len;
    }

    uint8_t *serial_tmp = (uint8_t *) calloc(total_size, sizeof(uint8_t));
    uint8_t *dst = serial_tmp;

    if (serial_tmp == NULL)
    {
        printf("calloc failed\n");
        return -1;
    }

    memcpy(dst, &total_size, sizeof(uint64_t));
    dst += sizeof(uint64_t);

    memcpy(dst, &request_type, sizeof(uint64_t));
    dst += sizeof(uint64_t);

    memcpy(dst, &kek_id_len, sizeof(uint64_t));
    dst += sizeof(uint64_t);

    memcpy(dst, kek_id, kek_id_len);
    dst += kek_id_len;

    memcpy(dst, &cipher_len, sizeof(uint64_t));
    dst += sizeof(uint64_t);

    memcpy(dst, WRAP_CIPHER, cipher_len);
    dst += cipher_len;

    memcpy(dst, &dek_len, sizeof(uint64_t));
    dst += sizeof(uint64_t);

    memcpy(dst, dek, dek_len);
    dst += dek_len;

    // Decrypt requests always serialize iv and tag fields, although they may be empty.
    if (request_type == PELZ_REQ_DEC_SIGNED)
    {
        memcpy(dst, &iv_len, sizeof(uint64_t));
        dst += sizeof(uint64_t);

        dst += iv_len;

        memcpy(dst, &tag_len, sizeof(uint64_t));
        dst += sizeof(uint64_t);

        dst += tag_len;
    }

    memcpy(dst, &cert_len, sizeof(uint64_t));
    dst += sizeof(uint64_t);

    memcpy(dst, cert, cert_len);
    dst += cert_len;

    uint64_t written_size = (uint64_t) (dst - serial_tmp);
    if (written_size != total_size)
    {
        printf("serialization length is incorrect. calculated size: %lu, written size: %lu\n", total_size, written_size);
        free(serial_tmp);
        return -1;
    }

    *serial = serial_tmp;
    *serial_len = (size_t) total_size;
    return 0;
}

int generate_request_signature(uint8_t *serial, size_t serial_len, const uint8_t *key_data, size_t key_data_len, uint8_t **signature, size_t *signature_len)
{
    // The signature parameters need to be compatible on ec_verify_buffer in kmyth

    EVP_PKEY *sign_pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &key_data, key_data_len);
    if (sign_pkey == NULL)
    {
        printf("failed to convert pkey\n");
        return -1;
    }

    // create message digest context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        printf("creation of message digest context failed\n");
        return -1;
    }

    // configure signing context
    if (EVP_SignInit(mdctx, EVP_sha512()) != 1)
    {
        printf("config of message digest signature context failed\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // hash data into the signature context
    if (EVP_SignUpdate(mdctx, serial, serial_len) != 1)
    {
        printf("error hashing data into signature context\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // allocate memory for signature
    int max_sig_len = EVP_PKEY_size(sign_pkey);
    if (max_sig_len <= 0)
    {
        printf("invalid value for maximum signature length\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    *signature = (uint8_t *) calloc((size_t)max_sig_len, sizeof(unsigned char));
    if (*signature == NULL)
    {
        printf("malloc of signature buffer failed\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // sign the data (create signature)
    if (EVP_SignFinal(mdctx, *signature, (unsigned int *) signature_len, sign_pkey) != 1)
    {
        printf("signature creation failed\n");
        free(*signature);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // done - clean-up context
    EVP_MD_CTX_free(mdctx);

    return 0;
}

int create_pelz_request(int request_type, const char *kek_id, uint8_t *dek, size_t dek_len, char *key_path, char *cert_path, char **request_msg)
{
    int ret;
    cJSON *request;
    uint8_t *sign_key;
    size_t sign_key_len;
    uint8_t *sign_cert;
    size_t sign_cert_len;
    uint8_t *serial;
    size_t serial_len;
    uint8_t *signature;
    size_t signature_len;
    char *encoded_signature;
    size_t encoded_signature_len;
    char *encoded_cert;
    size_t encoded_cert_len;
    char *encoded_dek;
    size_t encoded_dek_len;

    if (read_bytes_from_file(key_path, &sign_key, &sign_key_len)) {
        printf("failed to read the file at %s.\n", key_path);
        return -1;
    }

    if (read_bytes_from_file(cert_path, &sign_cert, &sign_cert_len)) {
        printf("failed to read the file at %s.\n", cert_path);
        free(sign_key);
        return -1;
    }

    ret = serialize_request(request_type, kek_id, dek, dek_len, sign_cert, sign_cert_len, &serial, &serial_len);
    if (ret != 0)
    {
        printf("serialization failed\n");
        free(sign_key);
        free(sign_cert);
        return -1;
    }

    generate_request_signature(serial, serial_len, sign_key, sign_key_len, &signature, &signature_len);
    free(serial);
    free(sign_key);
    sign_key = NULL;
    if (ret != 0)
    {
        printf("signing failed\n");
        free(sign_cert);
        return -1;
    }

    ret = encodeBase64Data(signature, signature_len, (uint8_t **) &encoded_signature, &encoded_signature_len);
    free(signature);
    signature = NULL;
    if (ret != 0)
    {
        printf("signature base-64 encoding failed\n");
        free(sign_cert);
        return -1;
    }

    ret = encodeBase64Data(sign_cert, sign_cert_len, (uint8_t **) &encoded_cert, &encoded_cert_len);
    free(sign_cert);
    if (ret != 0)
    {
        printf("certificate base-64 encoding failed\n");
        free(encoded_signature);
        return -1;
    }

    ret = encodeBase64Data(dek, dek_len, (uint8_t **) &encoded_dek, &encoded_dek_len);
    if (ret != 0)
    {
        printf("data base-64 encoding failed\n");
        free(encoded_signature);
        free(encoded_cert);
        return -1;
    }

    request = cJSON_CreateObject();
    if (request == NULL)
    {
        printf("cJSON_CreateObject error\n");
        free(encoded_signature);
        free(encoded_cert);
        free(encoded_dek);
        return -1;
    }

    cJSON_AddItemToObject(request, "request_type", cJSON_CreateNumber(request_type));
    cJSON_AddItemToObject(request, "cipher", cJSON_CreateString(WRAP_CIPHER));
    cJSON_AddItemToObject(request, "key_id", cJSON_CreateString(kek_id));

    cJSON_AddItemToObject(request, "data", cJSON_CreateString(encoded_dek));
    free(encoded_dek);
    encoded_dek = NULL;

    cJSON_AddItemToObject(request, "request_sig", cJSON_CreateString(encoded_signature));
    free(encoded_signature);

    cJSON_AddItemToObject(request, "requestor_cert", cJSON_CreateString(encoded_cert));
    free(encoded_cert);

    // Note: we don't include the tag or iv fields because pelz will not accept empty strings in json requests

    *request_msg = cJSON_PrintUnformatted(request);

    cJSON_Delete(request);

    return 0;
}

int decode_response_data(char *json_str, uint8_t **data, size_t *len)
{
    cJSON *json = cJSON_Parse(json_str);
    if (json == NULL)
    {
        printf("cJSON_Parse error\n");
        return -1;
    }

    const char *field_name = "data";
    const cJSON *field = cJSON_GetObjectItemCaseSensitive(json, field_name);
    if (!cJSON_IsString(field) || field->valuestring == NULL)
    {
        printf("Missing JSON field: %s\n", field_name);
        cJSON_Delete(json);
        return -1;
    }

    if (decodeBase64Data((unsigned char *) field->valuestring, strlen(field->valuestring),
                         data, len))
    {
        printf("decodeBase64Data error\n");
        cJSON_Delete(json);
        return -1;
    }

    cJSON_Delete(json);
    return 0;
}

int encrypt_wrap_store(uint8_t *data, size_t data_len, const char *kek_id, char *out_path, char *key_path, char *cert_path)
{
    if (strlen(kek_id) > KEK_ID_SIZE)
    {
        printf("kek id is too long\n");
        return -1;
    }

    size_t bundle_len = sizeof(encrypt_bundle) + data_len;
    encrypt_bundle *bundle = (encrypt_bundle *) calloc(bundle_len, sizeof(uint8_t));
    if (bundle == NULL)
    {
        printf("allocation error\n");
        return -1;
    }

    uint32_t ret_status;
    sgx_status_t sgx_status;
    sgx_status = demo_encrypt(initiator_enclave_id, &ret_status, data, data_len, (uint8_t *) bundle, bundle_len);
    if (sgx_status != SGX_SUCCESS || ret_status != 0) {
        printf("encrypt_data Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", sgx_status, ret_status);
        free(bundle);
        return -1;
    }

    char *request;
    ret_status = create_pelz_request(PELZ_REQ_ENC_SIGNED, kek_id, bundle->key, sizeof(bundle->key), key_path, cert_path, &request);
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

    size_t content_len = sizeof(encrypt_file_content) + data_len;
    encrypt_file_content *content = (encrypt_file_content *) calloc(content_len, sizeof(uint8_t));
    if (content == NULL)
    {
        printf("allocation error\n");
        free(bundle);
        free(wrapped_dek);
        return -1;
    }

    memcpy(content->wrapped_key, wrapped_dek, KEY_SIZE_WRAPPED);
    free(wrapped_dek);

    memcpy(content->tag, bundle->tag, TAG_SIZE);
    memcpy(content->iv, bundle->iv, IV_SIZE);
    memcpy(content->cipher_data, bundle->cipher_data, data_len);

    free(bundle);

    memcpy(content->format_code, ENCRYPT_FORMAT, sizeof(content->format_code));
    memcpy(content->kek_id, kek_id, strlen(kek_id));

    if (write_bytes_to_file(out_path, (uint8_t *) content, content_len))
    {
        printf("file write error\n");
        free(content);
        return -1;
    }

    free(content);

    return 0;
}

int unwrap_dek(const char *kek_id, uint8_t *wrapped_key, char *key_path, char *cert_path, uint8_t *unwrapped_key)
{
    int ret;
    char *request;
    ret = create_pelz_request(PELZ_REQ_DEC_SIGNED, (const char *) kek_id, wrapped_key, KEY_SIZE_WRAPPED, key_path, cert_path, &request);
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
    memcpy(unwrapped_key, dek, KEY_SIZE);
    free(dek);

    return 0;
}

int make_decryption_bundle(uint8_t *file_data, size_t content_len, char *key_path, char *cert_path, uint8_t **bundle_data, size_t *bundle_len)
{
    if (content_len <= sizeof(encrypt_file_content))
    {
        printf("Invalid data file (size).");
        return -1;
    }

    encrypt_file_content *content = (encrypt_file_content *) file_data;
    if (strncmp((char *) content->format_code, ENCRYPT_FORMAT, sizeof(content->format_code)) != 0)
    {
        printf("Invalid data file (format code).");
        return -1;
    }

    size_t encrypt_data_len = content_len - sizeof(encrypt_file_content);
    size_t tmp_bundle_len = sizeof(encrypt_bundle) + encrypt_data_len;
    encrypt_bundle *bundle = (encrypt_bundle *) calloc(tmp_bundle_len, sizeof(uint8_t));
    if (bundle == NULL)
    {
        printf("allocation error\n");
        return -1;
    }

    if (unwrap_dek(content->kek_id, content->wrapped_key, key_path, cert_path, bundle->key))
    {
        printf("pelz unwrapping failed\n");
        free(bundle);
        return -1;
    }

    memcpy(bundle->tag, content->tag, TAG_SIZE);
    memcpy(bundle->iv, content->iv, IV_SIZE);
    memcpy(bundle->cipher_data, content->cipher_data, encrypt_data_len);

    *bundle_data = (uint8_t *) bundle;
    *bundle_len = tmp_bundle_len;

    return 0;
}

int unwrap_decrypt_store(uint8_t *file_data, size_t content_len, char *out_path, char *key_path, char *cert_path)
{
    uint8_t *bundle_data = NULL;
    size_t bundle_len = 0;
    if (make_decryption_bundle(file_data, content_len, key_path, cert_path, &bundle_data, &bundle_len))
    {
        printf("decryption error\n");
        return -1;
    }

    size_t decrypt_data_len = bundle_len - sizeof(encrypt_bundle);
    uint8_t *decrypt_data = (uint8_t *) calloc(decrypt_data_len, sizeof(uint8_t));
    if (decrypt_data == NULL)
    {
        printf("allocation error\n");
        free(bundle_data);
        return -1;
    }

    uint32_t ret_status;
    sgx_status_t sgx_status;
    sgx_status = demo_decrypt(initiator_enclave_id, &ret_status, bundle_data, bundle_len, decrypt_data, decrypt_data_len);
    free(bundle_data);
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

int unwrap_decrypt_search(uint8_t *file_data, size_t content_len, char *search_term, char *key_path, char *cert_path)
{
    uint8_t *bundle_data = NULL;
    size_t bundle_len = 0;
    if (make_decryption_bundle(file_data, content_len, key_path, cert_path, &bundle_data, &bundle_len))
    {
        printf("decryption error\n");
        return -1;
    }

    int result_count;
    uint32_t ret_status;
    sgx_status_t sgx_status;
    sgx_status = demo_decrypt_search(initiator_enclave_id, &ret_status, bundle_data, bundle_len, search_term, &result_count);
    free(bundle_data);
    if (sgx_status != SGX_SUCCESS || ret_status != 0) {
        printf("decrypt_search_data Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", sgx_status, ret_status);
        return -1;
    }

    printf("SEARCH RESULT: search for %s found %d occurrences\n", search_term, result_count);

    return 0;
}

int establish_secure_channel()
{
    uint32_t ret_status;
    sgx_status_t status;

    // Establish the socket connection that will be used to communicate with pelz
    if (connect_to_remote(REMOTE_ADDR, REMOTE_PORT) == -1) {
        printf("failed to connect to pelz.\n");
        return -1;
    }

    // establish an ECDH session with the responder enclave running in another process
    status = test_create_session(initiator_enclave_id, &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
        printf("failed to establish secure channel: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        return -1;
    }
    printf("Established secure channel.\n");
    return 0;
}

int close_secure_channel()
{
    uint32_t ret_status;
    sgx_status_t status;

    // close ECDH session
    status = test_close_session(initiator_enclave_id, &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
        printf("test_close_session Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        return -1;
    }
    printf("Closed secure channel.\n");
    return 0;
}

int execute_command(int argc, char* argv[])
{
    static struct option long_opts[] =
    {
        {"input-file", required_argument, 0, 'i'},
        {"output-file", required_argument, 0, 'o'},
        {"signing-key", required_argument, 0, 'r'},
        {"signing-cert", required_argument, 0, 'u'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int options;
    int option_index = 0;

    uint8_t *data = NULL;
    size_t data_len = 0;
    char *out_path = NULL;
    char *key_path = NULL;
    char *cert_path = NULL;

    while ((options = getopt_long(argc, argv, "i:o:r:u:h", long_opts, &option_index)) != -1)
    {
        switch (options)
        {
        case 'i':
            if (read_bytes_from_file(optarg, &data, &data_len)) {
                printf("failed to read the input data file at %s.\n", optarg);
                return -1;
            }
            break;
        case 'o':
            out_path = strdup(optarg);
            break;
        case 'r':
            key_path = strdup(optarg);
            break;
        case 'u':
            cert_path = strdup(optarg);
            break;
        case 'h':
            print_usage(argv[0]);
            return -1;
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    if (optind >= argc)
    {
        print_usage(argv[0]);
        return -1;
    }
    char *command = argv[optind++];

    if (strcmp(command, "encrypt") == 0)
    {
        if (!data || !out_path || !key_path || !cert_path || optind != argc - 1)
        {
            printf("invalid arguments for \"%s\" command\n", command);
            print_usage(argv[0]);
            return -1;
        }
        char *kek_id = argv[optind];
        if (encrypt_wrap_store(data, data_len, kek_id, out_path, key_path, cert_path)) {
            printf("encrypt_wrap failed\n");
            return -1;
        }
    }
    else if (strcmp(command, "decrypt") == 0)
    {
        if (!data || !out_path || !key_path || !cert_path || optind != argc)
        {
            printf("invalid arguments for \"%s\" command\n", command);
            print_usage(argv[0]);
            return -1;
        }
        if (unwrap_decrypt_store(data, data_len, out_path, key_path, cert_path)) {
            printf("unwrap_decrypt failed\n");
            return -1;
        }
    }
    else if (strcmp(command, "search") == 0)
    {
        if (!data || out_path || !key_path || !cert_path || optind != argc - 1)
        {
            printf("invalid arguments for \"%s\" command\n", command);
            print_usage(argv[0]);
            return -1;
        }
        char *keyword = argv[optind];
        if (unwrap_decrypt_search(data, data_len, keyword, key_path, cert_path)) {
            printf("unwrap_decrypt_search failed\n");
            return -1;
        }
    }
    else
    {
        printf("Invalid command line arguments.\n");
        print_usage(argv[0]);
        return -1;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    int update = 0;
    sgx_launch_token_t token = {0};
    sgx_status_t status;

    // create ECDH initiator enclave
    status = sgx_create_enclave(ENCLAVE_INITIATOR_NAME, SGX_DEBUG_FLAG, &token, &update, &initiator_enclave_id, NULL);
    if (status != SGX_SUCCESS) {
        printf("failed to load enclave %s, error code is 0x%x.\n", ENCLAVE_INITIATOR_NAME, status);
        return -1;
    }
    printf("Loaded enclave %s\n", ENCLAVE_INITIATOR_NAME);

    if (establish_secure_channel())
    {
        sgx_destroy_enclave(initiator_enclave_id);
    }

    execute_command(argc, argv);

    close_secure_channel();
    sgx_destroy_enclave(initiator_enclave_id);

    return 0;
}
