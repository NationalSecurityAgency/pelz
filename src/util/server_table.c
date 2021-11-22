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

#include <common_table.h>
#include <charbuf.h>
#include <pelz_log.h>

#include "sgx_trts.h"
#include "pelz_enclave_t.h"
#include "kmyth_enclave_trusted.h"
#include "ec_key_cert_unmarshal.h"

EVP_PKEY *private_pkey;

TableResponseStatus server_table_add(uint64_t handle)
{
  Entry tmp_entry;
  size_t max_mem_size;
  X509 *tmpcert;
  uint8_t *data;
  size_t data_size = 0;
  int ret;
  char *tmp_id;
  int index = 0;

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

  tmp_id = X509_NAME_oneline(X509_get_subject_name(tmp_entry.value.cert), NULL, 0);
  tmp_entry.id = new_charbuf(strlen(tmp_id));
  if (strlen(tmp_id) != tmp_entry.id.len)
  {
    pelz_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }

  memcpy(tmp_entry.id.chars, tmp_id, tmp_entry.id.len);
  print_server_info(&ret, tmp_entry.id.len, tmp_entry.id.chars);
  print_key_info(&ret, tmp_entry.id);
  if (table_lookup(SERVER, tmp_entry.id, &index) == 0)
  {
    tmpcert = server_table.entries[index].value.cert;
    if (X509_cmp(tmpcert, tmp_entry.value.cert) == 0)
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

TableResponseStatus private_pkey_init(void)
{
  private_pkey = EVP_PKEY_new();
  if (private_pkey == NULL)
  {
    pelz_log(LOG_ERR, "Error allocating EVP_PKEY");
    return ERR;
  }
  return OK;
}

TableResponseStatus private_pkey_free(void)
{
  EVP_PKEY_free(private_pkey);
  return OK;
}

TableResponseStatus private_pkey_add(uint64_t handle)
{
  uint8_t *data;
  size_t data_size = 0;

  data_size = retrieve_from_unseal_table(handle, &data);
  if (data_size == 0)
  {
    pelz_log(LOG_ERR, "Failure to retrive data from unseal table.");
    return ERR;
  }

  if (unmarshal_ec_der_to_pkey(&data, &data_size, &private_pkey) == 1)
  {
    pelz_log(LOG_ERR, "Failure to unmarshal ec_der to pkey");
    free(data);
    return ERR;
  }

  free(data);
  return OK;
}
