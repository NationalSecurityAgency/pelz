#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdbool.h>
#include <string.h>


#include ENCLAVE_HEADER_TRUSTED
#include "kmyth_enclave_trusted.h"
#include "charbuf.h"
#include "enclave_request_signing.h"
#include "pelz_enclave.h"
#include "common_table.h"
#include "ca_table.h"
#include "ecdh_util.h"




charbuf serialize_request(RequestType request_type, charbuf key_id, charbuf data, charbuf requestor_cert)
{
  uint64_t request_type_int = (uint64_t)request_type;

  // TODO: Handle the overflow cases here
  uint64_t total_size = (5*sizeof(uint64_t)) + key_id.len + data.len + requestor_cert.len;

  charbuf serialized = new_charbuf(total_size);
  if(serialized.chars == NULL)
  {
    return serialized;
  }

  unsigned char* dst = serialized.chars;

  memcpy(dst, &total_size, sizeof(uint64_t));
  dst += sizeof(uint64_t);
  
  memcpy(dst, &request_type_int, sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, (uint64_t*)(&key_id.len), sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, key_id.chars, key_id.len);
  dst += key_id.len;

  memcpy(dst, (uint64_t*)(&data.len), sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, data.chars, data.len);
  dst += data.len;

  memcpy(dst, (uint64_t*)(&requestor_cert.len), sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, requestor_cert.chars, requestor_cert.len);
  return serialized;
}
  
bool validate_signature(RequestType request_type, charbuf key_id, charbuf data, charbuf signature, charbuf cert)
{
  bool result = false;
  X509* requestor_x509;
  EVP_PKEY *requestor_pubkey;
  charbuf serialized;

  requestor_x509 = d2i_X509(NULL, (const unsigned char**)&(cert.chars), cert.len);
  if(requestor_x509 == NULL)
  {
    return result;
  }

  /* Check that the requestors cert is signed by a known CA */
  if(validate_cert(requestor_x509) != true)
  {
    X509_free(requestor_x509);
    return result;
  }

  /* Now validate the signature over the request */
  requestor_pubkey = X509_get_pubkey(requestor_x509);
  if(requestor_pubkey == NULL)
  {
    X509_free(requestor_x509);
    return result;
  }

  serialized = serialize_request(request_type, key_id, data, cert);
  if(serialized.chars == NULL)
  {
    X509_free(requestor_x509);
    EVP_PKEY_free(requestor_pubkey);
    return result;
  }

  result = verify_buffer(requestor_pubkey, serialized.chars, serialized.len, signature.chars, signature.len);
  free_charbuf(&serialized);
  X509_free(requestor_x509);
  EVP_PKEY_free(requestor_pubkey);
  return result;
}
