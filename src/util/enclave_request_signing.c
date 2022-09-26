#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <string.h>


#include ENCLAVE_HEADER_TRUSTED
#include "kmyth_enclave_trusted.h"
#include "charbuf.h"
#include "enclave_request_signing.h"
#include "pelz_enclave.h"
#include "common_table.h"
#include "ca_table.h"
#include "ecdh_util.h"




charbuf serialize_request(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf data, charbuf iv, charbuf tag, charbuf requestor_cert)
{
  uint64_t num_fields = 5;
  if(request_type == REQ_DEC_SIGNED || request_type == REQ_DEC)
  {
    // If there's a mismatch between NULL chars and length in tag or IV
    // that's an indication something odd is happening, so error out.
    if((iv.chars == NULL && iv.len != 0) ||
       (iv.chars != NULL && iv.len == 0) ||
       (tag.chars == NULL && tag.len != 0) ||
       (tag.chars != NULL && tag.len == 0))
    {
      return new_charbuf(0);
    }

    // Decrypt requests have 2 extra fields, IV and tag (which can be empty).
    num_fields = 7;
  }

  // If it's not a decrypt request there shouldn't be an IV or tag.
  else{
    if(tag.chars != NULL || tag.len != 0 || iv.chars != NULL || iv.len != 0)
    {
      return new_charbuf(0);
    }
  }
  uint64_t request_type_int = (uint64_t)request_type;

  uint64_t total_size = ((num_fields+1)*sizeof(uint64_t));
  if(total_size + key_id.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += key_id.len;

  if(total_size + cipher_name.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += cipher_name.len;

  if(total_size + data.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += data.len;

  if(total_size + iv.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += iv.len;

  if(total_size + tag.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += tag.len;

  if(total_size + requestor_cert.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += requestor_cert.len;

  
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

  memcpy(dst, (uint64_t*)(&cipher_name.len), sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, cipher_name.chars, cipher_name.len);
  dst += cipher_name.len;

  memcpy(dst, (uint64_t*)(&data.len), sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, data.chars, data.len);
  dst += data.len;

  // Decrypt requests always serialize iv and tag fields,
  // although they may be empty.
  if(request_type == REQ_DEC_SIGNED)
  {
    memcpy(dst, (uint64_t*)(&iv.len), sizeof(uint64_t));
    dst += sizeof(uint64_t);

    memcpy(dst, iv.chars, iv.len);
    dst += iv.len;

    memcpy(dst, (uint64_t*)(&tag.len), sizeof(uint64_t));
    dst += sizeof(uint64_t);

    memcpy(dst, tag.chars, tag.len);
    dst += tag.len;
  }

  memcpy(dst, (uint64_t*)(&requestor_cert.len), sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, requestor_cert.chars, requestor_cert.len);
  return serialized;
}
  
int validate_signature(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf data, charbuf iv, charbuf tag, charbuf signature, charbuf cert)
{
  int result = 1;
  X509* requestor_x509;
  EVP_PKEY *requestor_pubkey;
  charbuf serialized;

  const unsigned char* cert_ptr = cert.chars;
  
  requestor_x509 = d2i_X509(NULL, &cert_ptr, cert.len);
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

  serialized = serialize_request(request_type, key_id, cipher_name, data, iv, tag, cert);
  if(serialized.chars == NULL || serialized.len == 0)
  {
    X509_free(requestor_x509);
    EVP_PKEY_free(requestor_pubkey);
    return result;
  }

  if(verify_buffer(requestor_pubkey, serialized.chars, serialized.len, signature.chars, signature.len) == EXIT_SUCCESS)
  {
    result = 0;
  }
  free_charbuf(&serialized);
  X509_free(requestor_x509);
  EVP_PKEY_free(requestor_pubkey);
  return result;
}
