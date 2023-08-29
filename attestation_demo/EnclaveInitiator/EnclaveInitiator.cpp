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


// Enclave1.cpp : Defines the exported functions for the .so application
#include "sgx_eid.h"
#include "EnclaveInitiator_t.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E1.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"
#include "sgx_utils.h"
#include <map>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "encrypt_datatypes.h"

#define UNUSED(val) (void)(val)

#define RESPONDER_PRODID 0

std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

dh_session_t g_session;


/* Function Description:
 *   This is ECALL routine to create ECDH session.
 *   When it succeeds to create ECDH session, the session context is saved in g_session.
 * */
extern "C" uint32_t test_create_session()
{
        return create_session(&g_session);
}

/* Function Description:
 *   This is ECALL routine to transfer message with ECDH peer
 * */
uint32_t sgx_make_pelz_request(char *req_msg, size_t req_msg_len, size_t max_resp_len, char *resp_buff, size_t *resp_len)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    char *out_buff;
    size_t out_buff_len = 0;

    ke_status = send_request_receive_response(&g_session, req_msg, req_msg_len,
                                                max_resp_len, &out_buff, &out_buff_len);
    if(ke_status != SUCCESS)
    {
        return ke_status;
    }

    memcpy(resp_buff, out_buff, max_resp_len);
    *resp_len = out_buff_len;

    SAFE_FREE(out_buff);
    return SUCCESS;
}

/* Function Description:
 *   This is ECALL interface to close secure session*/
uint32_t test_close_session()
{
    ATTESTATION_STATUS ke_status = SUCCESS;

    ke_status = close_session(&g_session);

    //Erase the session context
    memset(&g_session, 0, sizeof(dh_session_t));
    return ke_status;
}

/* Function Description:
 *   This is to verify peer enclave's identity.
 * For demonstration purpose, we verify below points:
 *   1. peer enclave's MRSIGNER is as expected
 *   2. peer enclave's PROD_ID is as expected
 *   3. peer enclave's attribute is reasonable: it's INITIALIZED'ed enclave; in non-debug build configuration, the enclave isn't loaded with enclave debug mode.
 **/
extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity, sgx_measurement_t *self_mr_signer)
{
    if (!peer_enclave_identity)
        return INVALID_PARAMETER_ERROR;

    // Check that both enclaves have the same MRSIGNER value
    if (memcmp((uint8_t *)&peer_enclave_identity->mr_signer, (uint8_t*)self_mr_signer, sizeof(sgx_measurement_t)))
        return ENCLAVE_TRUST_ERROR;

    // check peer enclave's product ID and enclave attribute (should be INITIALIZED'ed)
    if (peer_enclave_identity->isv_prod_id != RESPONDER_PRODID || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        return ENCLAVE_TRUST_ERROR;

    // check the enclave isn't loaded in enclave debug mode, except that the project is built for debug purpose
#if defined(NDEBUG)
    if (peer_enclave_identity->attributes.flags & SGX_FLAGS_DEBUG)
        return ENCLAVE_TRUST_ERROR;
#endif

    return SUCCESS;
}

/* Function Description: Operates on the input secret and generate the output secret
 * */
uint32_t get_message_exchange_response(uint32_t inp_secret_data)
{
    uint32_t secret_response;

    //User should use more complex encryption method to protect their secret, below is just a simple example
    secret_response = inp_secret_data & 0x11111111;

    return secret_response;

}

//Generates the response from the request message
/* Function Description:
 *   process request message and generate response
 * Parameter Description:
 *   [input] decrypted_data: this is pointer to decrypted message
 *   [output] resp_buffer: this is pointer to response message, the buffer is allocated inside this function
 *   [output] resp_length: this points to response length
 * */
extern "C" uint32_t message_exchange_response_generator(char* decrypted_data,
                                              char** resp_buffer,
                                              size_t* resp_length)
{
    ms_in_msg_exchange_t *ms;
    uint32_t inp_secret_data;
    uint32_t out_secret_data;
    if(!decrypted_data || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    ms = (ms_in_msg_exchange_t *)decrypted_data;

    if(umarshal_message_exchange_request(&inp_secret_data,ms) != SUCCESS)
        return ATTESTATION_ERROR;

    out_secret_data = get_message_exchange_response(inp_secret_data);

    if(marshal_message_exchange_response(resp_buffer, resp_length, out_secret_data) != SUCCESS)
        return MALLOC_ERROR;

    return SUCCESS;
}

uint32_t demo_decrypt(uint8_t *encrypt_data, size_t encrypt_data_len, uint8_t *decrypt_data, size_t decrypt_data_len)
{
    encrypt_bundle *bundle = (encrypt_bundle *) encrypt_data;

    // validate non-NULL buffers
    if (encrypt_data == NULL || encrypt_data_len == 0 || decrypt_data == NULL || decrypt_data_len == 0)
    {
        return 1;
    }

    if (sizeof(encrypt_bundle) + decrypt_data_len != encrypt_data_len)
    {
        return 1;
    }

    // initialize the cipher context to match cipher suite being used
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        return 1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // set tag to expected tag passed in with input data
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int) sizeof(bundle->tag), bundle->tag))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // set the IV length in the cipher context
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int) sizeof(bundle->iv), NULL))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // set the key and IV in the cipher context
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, bundle->key, bundle->iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // variables to hold/accumulate length returned by EVP library calls
    //   - OpenSSL insists this be an int
    int len = 0;
    size_t plaintext_len = 0;

    if (!EVP_DecryptUpdate(ctx, decrypt_data, &len, bundle->cipher_data, (int) decrypt_data_len) || len < 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    // We've already checked that len is non-negative.
    plaintext_len += (size_t) len;

    // 'Finalize' Decrypt:
    //   - validate that resultant tag matches the expected tag passed in
    //   - should produce no more plaintext bytes in our case
    if (EVP_DecryptFinal_ex(ctx, decrypt_data + plaintext_len, &len) <= 0 || len < 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    // We've already checked that len is non-negative
    plaintext_len += (size_t) len;

    // verify that the resultant PT length matches the input CT length
    if (plaintext_len != decrypt_data_len)
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // now that the decryption is complete, clean-up cipher context used
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

uint32_t demo_decrypt_search(uint8_t *encrypt_data, size_t encrypt_data_len, char *search_term, int *result_count)
{
    size_t decrypt_data_len = encrypt_data_len - sizeof(encrypt_bundle);
    uint8_t *decrypt_data = (uint8_t *) calloc(decrypt_data_len, sizeof(uint8_t));
    demo_decrypt(encrypt_data, encrypt_data_len, decrypt_data, decrypt_data_len);

    // search for substring in decrypted data
    size_t term_len = strlen(search_term);
    int count = 0;
    size_t search_idx = 0;
    size_t match_idx;
    for (search_idx=0; search_idx + term_len <= decrypt_data_len; search_idx++)
    {
        for (match_idx=0; match_idx<term_len; match_idx++)
        {
            if (decrypt_data[search_idx + match_idx] != search_term[match_idx])
            {
                break;
            }
        }
        if (match_idx == term_len) {
            count++;
        }
    }

    free(decrypt_data);

    *result_count = count;

    return 0;
}

uint32_t demo_encrypt(uint8_t *plain_data, size_t plain_data_len, uint8_t *encrypt_data, size_t encrypt_data_len)
{
    encrypt_bundle *bundle = (encrypt_bundle *) encrypt_data;

    // validate non-NULL buffers
    if (plain_data == NULL || plain_data_len == 0 || encrypt_data == NULL || encrypt_data_len == 0)
    {
        return 1;
    }

    if (sizeof(encrypt_bundle) + plain_data_len != encrypt_data_len)
    {
        return 1;
    }

    // Create the random key.
    if (RAND_priv_bytes(bundle->key, sizeof(bundle->key)) != 1)
    {
        log_ocall("Key generation failed");
        return 1;
    }

    // Create the random IV.
    if (RAND_bytes(bundle->iv, sizeof(bundle->iv)) != 1)
    {
        log_ocall("IV generation failed");
        return 1;
    }

    // initialize the cipher context to match cipher suite being used
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        return 1;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // set the IV length in the cipher context
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int) sizeof(bundle->iv), NULL))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // set the key and IV in the cipher context
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, bundle->key, bundle->iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // variable to hold length of resulting CT - OpenSSL insists this be an int
    int ciphertext_len = 0;

    // encrypt the input plaintext, put result in the output ciphertext buffer
    if (!EVP_EncryptUpdate(ctx, bundle->cipher_data, &ciphertext_len, plain_data, (int)plain_data_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // verify that the resultant CT length matches the input PT length
    if ((size_t) ciphertext_len != plain_data_len)
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // OpenSSL requires a "finalize" operation. For AES/GCM no data is written.
    if (!EVP_EncryptFinal_ex(ctx, bundle->tag, &ciphertext_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // get the AES/GCM tag value
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int) sizeof(bundle->tag), bundle->tag))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // now that the encryption is complete, clean-up cipher context
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

/* Encrypt data and append IV and TAG to ciphertext.
 * Meant to be compatible with kmyth's aes_gcm.h
*/
uint32_t demo_encrypt_message_string(uint8_t *plaintext, size_t plain_len,
                                            uint8_t *ciphertext, size_t cipher_len)
{
    if (plain_len >= __UINT32_MAX__)
    {
        return 1;
    }

    if (cipher_len != (plain_len + SGX_AESGCM_MAC_SIZE))
    {
        return 1;
    }

    const uint8_t *aad = (const uint8_t *)(" ");
    uint32_t aad_len = 0;

    // Use a random IV.
    uint8_t *iv = ciphertext + plain_len;
    if (RAND_bytes(iv, SGX_AESGCM_IV_SIZE) != 1)
    {
        log_ocall("IV generation failed");
        return 1;
    }

    uint8_t *tag = ciphertext + plain_len + SGX_AESGCM_IV_SIZE;

    //Prepare the request message with the encrypted payload
    sgx_status_t status = sgx_rijndael128GCM_encrypt(&g_session.active.AEK,
                plaintext, (uint32_t) plain_len,
                ciphertext,
                iv, SGX_AESGCM_IV_SIZE,
                aad, aad_len,
                (sgx_aes_gcm_128bit_tag_t *) tag);

    return status;
}

/* Decrypt data with IV and TAG appended to ciphertext.
 * Meant to be compatible with kmyth's aes_gcm.h
 */
uint32_t demo_decrypt_message_string(uint8_t *ciphertext, size_t cipher_len,
                                            uint8_t *plaintext, size_t plain_len)
{
    if (plain_len >= __UINT32_MAX__)
    {
        return 1;
    }

    if (cipher_len != (plain_len + SGX_AESGCM_MAC_SIZE))
    {
        return 1;
    }

    //Additional authentication data is empty string
    const uint8_t *aad = (const uint8_t*)(" ");
    uint32_t aad_len = 0;

    uint8_t *iv = ciphertext + plain_len;
    uint8_t *tag = ciphertext + plain_len + SGX_AESGCM_IV_SIZE;

    sgx_status_t status = sgx_rijndael128GCM_decrypt(&g_session.active.AEK,
                ciphertext, (uint32_t) plain_len,
                plaintext,
                iv, SGX_AESGCM_IV_SIZE,
                aad, aad_len,
                (sgx_aes_gcm_128bit_tag_t *) tag);

    return status;
}
