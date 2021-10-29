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
#include <openssl/err.h>

#include <pelz_io.h>
#include <server_table.h>
#include <util.h>
#include <pelz_request_handler.h>
#include <charbuf.h>
#include <pelz_log.h>

#include "sgx_trts.h"
#include "pelz_enclave_t.h"
#include "kmyth_enclave_trusted.h"
#include "ec_key_cert_unmarshal.h"

ServerTable server_table = {
  .entries = NULL,
  .num_entries = 0,
  .mem_size = 0
};

EVP_PKEY *private_pkey;

//Destroy server table
int server_table_destroy(void)
{
  pelz_log(LOG_DEBUG, "Server Table Destroy Function Starting");
  for (unsigned int i = 0; i < server_table.num_entries; i++)
  {
    if (server_table.entries[i].server_id.len != 0)
    {
      free_charbuf(&server_table.entries[i].server_id);
    }
    if (server_table.entries[i].cert != NULL)
    {
      X509_free(server_table.entries[i].cert);
    }
  }

  //Free the storage allocated for the hash table
  free(server_table.entries);
  server_table.entries = NULL;
  server_table.num_entries = 0;
  server_table.mem_size = 0;
  pelz_log(LOG_DEBUG, "Server Table Destroy Function Complete");
  return (0);
}

int server_table_delete(charbuf server_id)
{
  int index;
  int data_size;

  index = 0;

  for (unsigned int i = 0; i < server_table.num_entries; i++)
  {
    if (cmp_charbuf(server_id, server_table.entries[i].server_id) == 0)
    {
      data_size = i2d_X509(server_table.entries[i].cert, NULL);
      server_table.mem_size = server_table.mem_size -
        ((server_table.entries[i].server_id.len * sizeof(char)) + sizeof(size_t) + data_size);
      free_charbuf(&server_table.entries[i].server_id);
      X509_free(server_table.entries[i].cert);
      index = i + 1;
      break;
    }
  }
  if (index == 0)
  {
    pelz_log(LOG_ERR, "Server ID not found.");
    return (1);
  }
  else if (server_table.mem_size == 0)
  {
    free(server_table.entries);
    server_table.entries = NULL;
    server_table.num_entries = 0;
  }
  else
  {
    for (unsigned int i = index; i < server_table.num_entries; i++)
    {
      server_table.entries[i - 1] = server_table.entries[i];
    }
    server_table.num_entries -= 1;

    CertEntry *temp;

    if ((temp = (CertEntry *) realloc(server_table.entries, (server_table.num_entries) * sizeof(CertEntry))) == NULL)
    {
      pelz_log(LOG_ERR, "Server List Space Reallocation Error");
      return (1);
    }
    else
    {
      server_table.entries = temp;
    }
  }
  return (0);
}

int server_table_add(uint64_t handle)
{
  CertEntry tmp_entry;
  size_t max_mem_size;
  X509 *tmpcert;
  uint8_t *data;
  size_t data_size = 0;
  int ret;
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

  ret = unmarshal_ec_der_to_x509(&data, &data_size, &tmp_entry.cert);
  if (ret)
  {
    pelz_log(LOG_ERR, "Unmarshal DER to X509 Failure");
    free(data);
    return ERR_X509;
  }
  free(data);

  tmp_id = X509_NAME_oneline(X509_get_subject_name(tmp_entry.cert), NULL, 0);
  tmp_entry.server_id = new_charbuf(strlen(tmp_id));
  if (strlen(tmp_id) != tmp_entry.server_id.len)
  {
    pelz_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }

  memcpy(tmp_entry.server_id.chars, tmp_id, tmp_entry.server_id.len);
  if (!server_table_lookup(tmp_entry.server_id, &tmpcert))
  {
    if (X509_cmp(tmpcert, tmp_entry.cert) == 0)
    {
      pelz_log(LOG_DEBUG, "Cert already added.");
      free_charbuf(&tmp_entry.server_id);
      X509_free(tmp_entry.cert);
      return OK;
    }
    else
    {
      pelz_log(LOG_ERR, "Cert entry and Server ID lookup do not match.");
      free_charbuf(&tmp_entry.server_id);
      X509_free(tmp_entry.cert);
      return NO_MATCH;
    }
  }

  CertEntry *temp;

  if ((temp = (CertEntry *) realloc(server_table.entries, (server_table.num_entries + 1) * sizeof(CertEntry))) == NULL)
  {
    pelz_log(LOG_ERR, "Cert List Space Reallocation Error");
    free_charbuf(&tmp_entry.server_id);
    X509_free(tmp_entry.cert);
    return ERR_REALLOC;
  }
  else
  {
    server_table.entries = temp;
  }
  server_table.entries[server_table.num_entries] = tmp_entry;
  server_table.num_entries++;
  server_table.mem_size = server_table.mem_size + (tmp_entry.server_id.len * sizeof(char)) + sizeof(size_t) + data_size;
  pelz_log(LOG_INFO, "Cert Added");
  return OK;
}

int server_table_lookup(charbuf server_id, X509 ** cert)
{
  for (unsigned int i = 0; i < server_table.num_entries; i++)
  {
    if (cmp_charbuf(server_id, server_table.entries[i].server_id) == 0)
    {
      *cert = server_table.entries[i].cert;
      return (0);
    }
  }
  return (1);
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
