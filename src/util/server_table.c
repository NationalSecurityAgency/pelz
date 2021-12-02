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

#include <pelz_io.h>
#include <common_table.h>
#include <util.h>
#include <pelz_request_handler.h>
#include <charbuf.h>
#include <pelz_log.h>

#include "sgx_trts.h"
#include "pelz_enclave_t.h"
#include "kmyth_enclave_trusted.h"
#include "ec_key_cert_unmarshal.h"

EVP_PKEY *private_pkey;

int server_table_add(uint64_t handle)
{
  Entry tmp_entry;
  size_t max_mem_size;
  uint8_t *data;
  size_t data_size = 0;
  int ret;
  int index = 0;
  int lastpos = 0;
  size_t len = 0;
  char *tmp_id;

  max_mem_size = 1000000;

  if (server_table.mem_size >= max_mem_size)
  {
    pelz_log(LOG_ERR, "Server Table memory allocation greater then specified limit.");
    return MEM_ALLOC_FAIL;
  }

  data_size = retrieve_from_unseal_table(handle, &data);
  if (data_size == 0)
  {
    pelz_log(LOG_ERR, "Failure to retrive data from unseal table.");
    return RET_FAIL;
  }

  ret = unmarshal_ec_der_to_x509(&data, &data_size, &tmp_entry.value.cert);
  if (ret)
  {
    pelz_log(LOG_ERR, "Unmarshal DER to X509 Failure");
    free(data);
    return ERR_X509;
  }
  free(data);

  X509_NAME *subj = X509_get_subject_name(tmp_entry.value.cert);

  if (subj == NULL)
  {
    pelz_log(LOG_ERR, "Could not parse certificate data");
    return ERR_X509;
  }

  //extract the common name from the  X509 subject name by the index location
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
  tmp_id = (char *) ASN1_STRING_get0_data(entry_data);

  tmp_entry.id = new_charbuf(len);
  if (len != tmp_entry.id.len)
  {
    pelz_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }
  memcpy(tmp_entry.id.chars, tmp_id, tmp_entry.id.len);
  if (table_lookup(SERVER, tmp_entry.id, &index) == 0)
  {
    if (X509_cmp(server_table.entries[index].value.cert, tmp_entry.value.cert) == 0)
    {
      pelz_log(LOG_DEBUG, "Cert already added.");
      free_charbuf(&tmp_entry.id);
      X509_free(tmp_entry.value.cert);
      return OK;
    }
    else
    {
      pelz_log(LOG_ERR, "Cert entry and Server ID lookup do not match.");
      free_charbuf(&tmp_entry.id);
      X509_free(tmp_entry.value.cert);
      return NO_MATCH;
    }
  }

  Entry *temp;

  if ((temp = (Entry *) realloc(server_table.entries, (server_table.num_entries + 1) * sizeof(Entry))) == NULL)
  {
    pelz_log(LOG_ERR, "Cert List Space Reallocation Error");
    free_charbuf(&tmp_entry.id);
    X509_free(tmp_entry.value.cert);
    return ERR_REALLOC;
  }
  else
  {
    server_table.entries = temp;
  }
  server_table.entries[server_table.num_entries] = tmp_entry;
  server_table.num_entries++;
  server_table.mem_size = server_table.mem_size + (tmp_entry.id.len * sizeof(char)) + sizeof(size_t) + data_size;
  pelz_log(LOG_INFO, "Cert Added");
  return OK;
}

int private_pkey_init(void)
{
  private_pkey = EVP_PKEY_new();
  if (private_pkey == NULL)
  {
    pelz_log(LOG_ERR, "Error allocating EVP_PKEY");
    return (1);
  }
  return (0);
}

int private_pkey_free(void)
{
  EVP_PKEY_free(private_pkey);
  return (0);
}

int private_pkey_add(uint64_t handle)
{
  uint8_t *data;
  size_t data_size = 0;

  data_size = retrieve_from_unseal_table(handle, &data);
  if (data_size == 0)
  {
    pelz_log(LOG_ERR, "Failure to retrive data from unseal table.");
    return (1);
  }

  if (unmarshal_ec_der_to_pkey(&data, &data_size, &private_pkey) == 1)
  {
    pelz_log(LOG_ERR, "Failure to unmarshal ec_der to pkey");
    free(data);
    return (1);
  }

  free(data);
  return (0);
}
