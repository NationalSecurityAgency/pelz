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

#include <pelz_io.h>
#include <common_table.h>
#include <server_table.h>
#include <util.h>
#include <pelz_request_handler.h>
#include <charbuf.h>
#include <pelz_log.h>

#include "sgx_trts.h"
#include "pelz_enclave_t.h"
#include "kmyth_enclave_trusted.h"
#include "ec_key_cert_unmarshal.h"

EVP_PKEY *private_pkey;

int server_table_add(charbuf server_id, uint64_t handle)
{
  Entry tmp_entry;
  size_t max_mem_size;
  charbuf tmpcert;
  uint8_t *data;
  size_t data_size = 0;
  int index = 0;

  max_mem_size = 1000000;

  if (server_table.mem_size >= max_mem_size)
  {
    pelz_log(LOG_ERR, "Server Table memory allocation greater then specified limit.");
    return MEM_ALLOC_FAIL;
  }

  tmp_entry.id = new_charbuf(server_id.len);
  if (server_id.len != tmp_entry.id.len)
  {
    pelz_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }

  memcpy(tmp_entry.id.chars, server_id.chars, tmp_entry.id.len);
  data_size = retrieve_from_unseal_table(handle, &data);
  if (data_size == 0)
  {
    pelz_log(LOG_ERR, "Failure to retrive data from unseal table.");
    return RET_FAIL;
  }

  tmp_entry.value.cert = new_charbuf(data_size);
  if (data_size != tmp_entry.value.cert.len)
  {
    pelz_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }

  memcpy(tmp_entry.value.cert.chars, data, tmp_entry.value.cert.len);

  if (table_lookup(SERVER, tmp_entry.id, &index) == 0)
  {
    tmpcert = new_charbuf(server_table.entries[index].value.cert.len);
    if (server_table.entries[index].value.cert.len != tmpcert.len)
    {
      pelz_log(LOG_ERR, "Charbuf creation error.");
      return (1);
    }
    memcpy(tmpcert.chars, server_table.entries[index].value.cert.chars, tmpcert.len);
    if (cmp_charbuf(tmpcert, tmp_entry.value.cert) == 0)
    {
      pelz_log(LOG_DEBUG, "Cert already added.");
      free_charbuf(&tmp_entry.id);
      secure_free_charbuf(&tmp_entry.value.cert);
      secure_free_charbuf(&tmpcert);
      return OK;
    }
    else
    {
      pelz_log(LOG_ERR, "Cert entry and Server ID lookup do not match.");
      free_charbuf(&tmp_entry.id);
      secure_free_charbuf(&tmp_entry.value.cert);
      secure_free_charbuf(&tmpcert);
      return NO_MATCH;
    }
  }

  Entry *temp;

  if ((temp = (Entry *) realloc(server_table.entries, (server_table.num_entries + 1) * sizeof(Entry))) == NULL)
  {
    pelz_log(LOG_ERR, "Cert List Space Reallocation Error");
    free_charbuf(&tmp_entry.id);
    secure_free_charbuf(&tmp_entry.value.cert);
    return ERR_REALLOC;
  }
  else
  {
    server_table.entries = temp;
  }
  server_table.entries[server_table.num_entries] = tmp_entry;
  server_table.num_entries++;
  server_table.mem_size =
    server_table.mem_size + ((tmp_entry.value.cert.len * sizeof(char)) + (tmp_entry.id.len * sizeof(char)) +
    (2 * sizeof(size_t)));
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
