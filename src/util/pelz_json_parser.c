/*
 * json_parser.c
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include <openssl/x509.h>

#include <pelz_json_parser.h>
#include <pelz_request_handler.h>
#include <charbuf.h>
#include <pelz_log.h>

#include "ecdh_util.h"

/**
 * <pre>
 * Helper function to extract string fields from JSON structs.
 * <pre>
 *
 * @param[in] json       The JSON structure.
 * @param[in] field_name The name of the desired field.
 *
 * @return A charbuf containing the data from the field, or a charbuf
 *         of length 0 on error.
 */
static charbuf get_JSON_string_field(cJSON* json, const char* field_name)
{
  charbuf field;
  if(!cJSON_HasObjectItem(json, field_name) || !cJSON_IsString(cJSON_GetObjectItem(json, field_name)))
  {
    pelz_log(LOG_ERR, "Missing JSON field %s.", field_name);
    return new_charbuf(0);
  } 
  if(cJSON_GetObjectItemCaseSensitive(json, field_name)->valuestring != NULL)
  {
    field = new_charbuf(strlen(cJSON_GetObjectItemCaseSensitive(json, field_name)->valuestring));
    if(field.len == 0 || field.chars == NULL)
    {  
      pelz_log(LOG_ERR, "Failed to allocate memory to extract JSON field %s.", field_name);
      return new_charbuf(0);
    }
    memcpy(field.chars, cJSON_GetObjectItemCaseSensitive(json, field_name)->valuestring, field.len);
  }
  else
  {
    pelz_log(LOG_ERR, "No value in JSON field %s.", field_name);
    return new_charbuf(0);
  }
  return field;
}

/**
 * <pre>
 * Helper function to extract fields from JSON structs. 
 * <pre>
 *
 * @param[in]  json       The JSON structure.
 * @param[in]  field_name The name of the desired field.
 * @param[out] value      Integer pointer to hold the extracted value.
 *
 * @return 0 on success, 1 error
 */
static int get_JSON_int_field(cJSON* json, const char* field_name, int* value)
{
  if(!cJSON_HasObjectItem(json, field_name) || !cJSON_IsNumber(cJSON_GetObjectItem(json, field_name)))
  {
    pelz_log(LOG_ERR, "Missing JSON field %s.", field_name);
    return 1;
  }
  *value = cJSON_GetObjectItemCaseSensitive(json, field_name)->valueint;
  return 0;
}


int request_decoder(charbuf request, RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * request_sig, charbuf * requestor_cert)
{
  cJSON *json;
  char *str = NULL;

  str = (char *) calloc((request.len + 1), sizeof(char));
  memcpy(str, request.chars, request.len);
  json = cJSON_Parse(str);
  free(str);
  if(get_JSON_int_field(json, "request_type", (int*)request_type))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: request_type.");
    cJSON_Delete(json);
    return (1);
  }

  // We always parse out key_id and data. Other parsing may
  // happen depending on the request type.
  *key_id = get_JSON_string_field(json, "key_id");
  if(key_id->len == 0 || key_id->chars == NULL)
  {
    pelz_log(LOG_ERR, "Failed to extract key_id from JSON.");
    cJSON_Delete(json);
    free_charbuf(key_id);
    return 1;
  }

  *data = get_JSON_string_field(json, "data");
  if(data->len == 0 || data->chars == NULL)
  {
    pelz_log(LOG_ERR, "Failed to exract data from JSON.");
    cJSON_Delete(json);
    free_charbuf(key_id);
    free_charbuf(data);
    return 1;
  }

  if(*request_type == REQ_ENC_SIGNED || *request_type == REQ_DEC_SIGNED)
  {
    *request_sig = get_JSON_string_field(json, "request_sig");
    if(request_sig->len == 0 || request_sig->chars == NULL)
    {
      cJSON_Delete(json);
      free_charbuf(key_id);
      free_charbuf(data);
      free_charbuf(request_sig);
      return 1;
    }

    *requestor_cert = get_JSON_string_field(json, "requestor_cert");
    if(requestor_cert->len == 0 || requestor_cert->chars == NULL)
    {
      cJSON_Delete(json);
      free_charbuf(key_id);
      free_charbuf(data);
      free_charbuf(request_sig);
      free_charbuf(requestor_cert);
      return 1;
    }
  }
  
  if ( validate_signature(request_type, key_id, data, request_sig, requestor_cert) )
  {
    pelz_log(LOG_ERR, "Signature Validation Error");
    cJSON_Delete(json);
    free_charbuf(key_id);
    free_charbuf(data);
    free_charbuf(request_sig);
    free_charbuf(requestor_cert);
    return (1);
  }
  cJSON_Delete(json);
  return (0);
}

int error_message_encoder(charbuf * message, const char *err_message)
{
  cJSON *root;
  char *tmp = NULL;

  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "error", cJSON_CreateString(err_message));
  if (cJSON_IsInvalid(root))
  {
    pelz_log(LOG_ERR, "JSON Message Creation Failed");
    cJSON_Delete(root);
    return (1);
  }
  tmp = cJSON_PrintUnformatted(root);
  *message = new_charbuf(strlen(tmp));
  memcpy(message->chars, tmp, message->len);
  cJSON_Delete(root);
  free(tmp);
  return (0);
}

int message_encoder(RequestType request_type, charbuf key_id, charbuf data, charbuf * message)
{
  cJSON *root;
  char *tmp = NULL;

  root = cJSON_CreateObject();
  switch (request_type)
  {
  case REQ_ENC:
    tmp = (char *) calloc((key_id.len + 1), sizeof(char));
    memcpy(tmp, key_id.chars, key_id.len);
    cJSON_AddItemToObject(root, "key_id", cJSON_CreateString(tmp));
    free(tmp);

    tmp = (char *) calloc((data.len + 1), sizeof(char));
    memcpy(tmp, data.chars, data.len);
    cJSON_AddItemToObject(root, "data", cJSON_CreateString(tmp));
    free(tmp);
    break;
  case REQ_DEC:
    tmp = (char *) calloc((key_id.len + 1), sizeof(char));
    memcpy(tmp, key_id.chars, key_id.len);
    cJSON_AddItemToObject(root, "key_id", cJSON_CreateString(tmp));
    free(tmp);

    tmp = (char *) calloc((data.len + 1), sizeof(char));
    memcpy(tmp, data.chars, data.len);
    cJSON_AddItemToObject(root, "data", cJSON_CreateString(tmp));
    free(tmp);
    break;
  default:
    pelz_log(LOG_ERR, "Request Type not recognized.");
    cJSON_Delete(root);
    return (1);
  }
  if (cJSON_IsInvalid(root))
  {
    pelz_log(LOG_ERR, "JSON Message Creation Failed");
    cJSON_Delete(root);
    return (1);
  }
  tmp = cJSON_PrintUnformatted(root);
  *message = new_charbuf(strlen(tmp));
  memcpy(message->chars, tmp, message->len);
  cJSON_Delete(root);
  free(tmp);
  return (0);
}

// TODO: Consider moving these functions to a separate source file

/* Concatenate request data for signing and validation. */
charbuf serialize_request_data(RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * requestor_cert)
{
  // Note: It may be possible to have collisions with this serialization because some field lengths are not fixed.

  uint16_t req_type = *request_type;
  size_t concat_len = sizeof(req_type) + key_id->len + requestor_cert->len + data->len;
  size_t place = 0;
  charbuf serial = new_charbuf(concat_len);

  if (serial.chars == NULL)
  {
    return serial;
  }

  req_type = htons(req_type);

  memcpy(serial.chars + place, &req_type, sizeof(req_type));
  place += sizeof(req_type);
  memcpy(serial.chars + place, key_id->chars, key_id->len);
  place += key_id->len;
  memcpy(serial.chars + place, requestor_cert->chars, requestor_cert->len);
  place += requestor_cert->len;
  memcpy(serial.chars + place, data->chars, data->len);
  place += data->len;

  return serial;
}

charbuf create_signature(EVP_PKEY * sign_pkey, RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * requestor_cert)
{
  // Note: This is included for demonstration/testing purposes.
  // A production implementation should run within SGX for data protection.

  int ret;
  charbuf signature = new_charbuf(0);
  unsigned char *sig_buff = NULL;
  unsigned int sig_len = 0;
  charbuf serial = serialize_request_data(request_type, key_id, data, requestor_cert);

  if (serial.chars == NULL)
  {
    return signature;
  }

  ret = sign_buffer(sign_pkey, serial.chars, serial.len, &sig_buff, &sig_len);

  free_charbuf(&serial);

  if (ret != EXIT_SUCCESS)
  {
    pelz_log(LOG_ERR, "sign_buffer failed");
    return signature;
  }

  signature = new_charbuf(sig_len);
  memcpy(signature.chars, sig_buff, sig_len);

  return signature;
}

X509 * load_cert(charbuf * requestor_cert)
{
  // create BIO wrapper for cert string
  BIO *cert_bio = BIO_new_mem_buf(requestor_cert->chars, requestor_cert->len);
  if (cert_bio == NULL)
  {
    pelz_log(LOG_ERR, "BIO creation failed");
    return NULL;
  }

  // load requestor's X509 certificate from BIO
  X509 *cert_x509 = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);

  BIO_free(cert_bio);
  cert_bio = NULL;

  if (cert_x509 == NULL)
  {
    pelz_log(LOG_ERR, "Requestor cert could not be read as PEM X509 format.");
    return NULL;
  }

  return cert_x509;
}

/* Check if the request cert is signed by a known CA. */
int check_cert_chain(X509 *requestor_x509) {
  // FIXME: not yet implemented

  // requires ecall to access stored CA certs

  return 0;
}


int validate_signature(RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * request_sig, charbuf * requestor_cert)
{
  // Note: This is vulnerable to signature replay attacks.

  int ret;
  X509 *requestor_x509;
  EVP_PKEY *requestor_pubkey;
  charbuf serial;

  // Extract the public key from requestor_cert
  requestor_x509 = load_cert(requestor_cert);
  if (requestor_x509 == NULL)
  {
    pelz_log(LOG_ERR, "load_cert failed");
    return 1;
  }

  requestor_pubkey = X509_get_pubkey(requestor_x509);
  if (requestor_pubkey == NULL)
  {
    pelz_log(LOG_ERR, "X509_get_pubkey failed");
    X509_free(requestor_x509);
    return 1;
  }

  serial = serialize_request_data(request_type, key_id, data, requestor_cert);
  if (serial.chars == NULL)
  {
    X509_free(requestor_x509);
    EVP_PKEY_free(requestor_pubkey);
    return 1;
  }

  /* Check that the request signature matches the request data. */
  ret = verify_buffer(requestor_pubkey, serial.chars, serial.len, request_sig->chars, request_sig->len);

  free_charbuf(&serial);
  EVP_PKEY_free(requestor_pubkey);

  if (ret)
  {
    X509_free(requestor_x509);
    return 1;
  }

  ret = check_cert_chain(requestor_x509);
  if (ret)
  {
    X509_free(requestor_x509);
    return 1;
  }

  X509_free(requestor_x509);
  requestor_x509 = NULL;

  return 0;
}
