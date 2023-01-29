/*
 * server_table.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>

#include <common_table.h>
#include <charbuf.h>
#include <pelz_enclave_log.h>

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED
#include "kmyth_enclave_trusted.h"
#include "ec_key_cert_unmarshal.h"
#include "server_table.h"

pelz_identity_t pelz_id;
//EVP_PKEY *private_pkey;

TableResponseStatus add_cert_to_table(TableType type, uint64_t handle)
{
  Entry tmp_entry;
  uint8_t * data = NULL;
  size_t data_size = 0;
  int ret;
  int index = 0;
  int lastpos = 0;
  size_t len = 0;
  const unsigned char *tmp_id;
  Table *table = get_table_by_type(type);

  if (table == NULL)
  {
    return ERR;
  }

  if (table->mem_size >= MAX_MEM_SIZE)
  {
    pelz_sgx_log(LOG_ERR, "Server Table memory allocation greater then specified limit.");
    return MEM_ALLOC_FAIL;
  }

  data_size = retrieve_from_unseal_table(handle, &data);
  if (data_size == 0)
  {
    pelz_sgx_log(LOG_ERR, "Failure to retrieve data from unseal table.");
    return RET_FAIL;
  }

  ret = unmarshal_ec_der_to_x509(data, data_size, &tmp_entry.value.cert);
  if (ret)
  {
    pelz_sgx_log(LOG_ERR, "Unmarshal DER to X509 Failure");
    free(data);
    return ERR_X509;
  }
  free(data);

  X509_NAME *subj = X509_get_subject_name(tmp_entry.value.cert);
  if (subj == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Could not parse certificate data");
    return ERR_X509;
  }

  //extract the common name from the X509 subject name by the index location
  //by iterating over the subject name to the last position
  for (;;)
  {
    int count = X509_NAME_get_index_by_NID(subj, NID_commonName, lastpos);

    if (count == -1)
    {
      break;
    }
    lastpos = count;
  }
  X509_NAME_ENTRY *entry = X509_NAME_get_entry(subj, lastpos);
  ASN1_STRING *entry_data = X509_NAME_ENTRY_get_data(entry);

  len = ASN1_STRING_length(entry_data);
  tmp_id = ASN1_STRING_get0_data(entry_data);

  tmp_entry.id = new_charbuf(len);
  if (len != tmp_entry.id.len)
  {
    pelz_sgx_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }
  memcpy(tmp_entry.id.chars, tmp_id, tmp_entry.id.len);
  if (table_lookup(type, tmp_entry.id, &index) == 0)
  {
    if (X509_cmp(table->entries[index].value.cert, tmp_entry.value.cert) == 0)
    {
      pelz_sgx_log(LOG_DEBUG, "Cert already added.");
      free_charbuf(&tmp_entry.id);
      X509_free(tmp_entry.value.cert);
      return OK;
    }
    else
    {
      pelz_sgx_log(LOG_ERR, "Cert entry and Server ID lookup do not match.");
      free_charbuf(&tmp_entry.id);
      X509_free(tmp_entry.value.cert);
      return NO_MATCH;
    }
  }

  Entry *temp;

  if ((temp = (Entry *) realloc(table->entries, (table->num_entries + 1) * sizeof(Entry))) == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Cert List Space Reallocation Error");
    free_charbuf(&tmp_entry.id);
    X509_free(tmp_entry.value.cert);
    return ERR_REALLOC;
  }
  else
  {
    table->entries = temp;
  }
  table->entries[table->num_entries] = tmp_entry;
  table->num_entries++;
  table->mem_size = table->mem_size + (tmp_entry.id.len * sizeof(char)) + sizeof(size_t) + data_size;
  pelz_sgx_log(LOG_INFO, "Cert Added");
  return OK;
}

TableResponseStatus private_pkey_init(void)
{
  pelz_id.private_pkey = EVP_PKEY_new();
  if (pelz_id.private_pkey == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Error allocating EVP_PKEY");
    return MEM_ALLOC_FAIL;
  }
  return OK;
}

TableResponseStatus private_pkey_free(void)
{
  EVP_PKEY_free(pelz_id.private_pkey);
  return OK;
}

TableResponseStatus private_pkey_add(uint64_t pkey_handle, uint64_t cert_handle)
{
  uint8_t *data;
  size_t data_size = 0;
  data_size = retrieve_from_unseal_table(pkey_handle, &data);
  if (data_size == 0)
  {
    pelz_sgx_log(LOG_ERR, "Failure to retrieve data from unseal table.");
    return RET_FAIL;
  }
  if (unmarshal_ec_der_to_pkey(data, data_size, &(pelz_id.private_pkey)) != EXIT_SUCCESS)
  {
    pelz_sgx_log(LOG_ERR, "Failure to unmarshal ec_der to pkey");
    free(data);
    return ERR_X509;
  }

  free(data);
  return OK;
}
