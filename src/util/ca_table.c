/*
 * ca_table.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <common_table.h>
#include <charbuf.h>
#include <pelz_enclave_log.h>

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED
#include "kmyth_enclave_trusted.h"


TableResponseStatus verify_cert(charbuf target_der)
{
  Table *table = get_table_by_type(CA_TABLE);
  if (table == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "get_table_by_type failed");
    return ERR;
  }

  const unsigned char* target_der_ptr = target_der.chars;

  X509 *target = d2i_X509(NULL, &target_der_ptr, target_der.len);
  if (target == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "DER to X509 format conversion failed");
    return ERR;
  }

  // Create cert store
  X509_STORE *store = X509_STORE_new();
  if (store == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "X509_STORE_new failed");
    return ERR;
  }

  // Put all ca certs in the store
  for (unsigned int i = 0; i < table->num_entries; i++)
  {
    X509 *cert = table->entries[i].value.cert;
    if (X509_STORE_add_cert(store, cert) != 1)
    {
      kmyth_sgx_log(LOG_ERR, "X509_STORE_add_cert failed");
      return ERR;
    }
  }

  // Create store context
  X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
  if (store_ctx == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "X509_STORE_CTX_new failed");
    return ERR;
  }

  if (X509_STORE_CTX_init(store_ctx, store, target, NULL) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "X509_STORE_CTX_init failed");
    return ERR;
  }

  int success = X509_verify_cert(store_ctx);

  X509_STORE_CTX_free(store_ctx);
  X509_STORE_free(store);
  X509_free(target);

  return (success == 1) ? OK : NO_MATCH;
}
