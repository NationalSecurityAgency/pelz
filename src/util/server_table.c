/*
 * server_table.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pelz_io.h>
#include <server_table.h>
#include <util.h>
#include <pelz_request_handler.h>
#include <charbuf.h>
#include <pelz_log.h>

#include "sgx_trts.h"
#include "pelz_enclave_t.h"
#include "kmyth_enclave.h"

ServerTable server_table;

//Initialize server table
int server_table_init(void)
{
  if ((server_table.entries = (CertEntry *) malloc(sizeof(CertEntry))) == NULL)
  {
    pelz_log(LOG_ERR, "Server List Space Allocation Error");
    return (1);
  }

  server_table.num_entries = 0;
  server_table.mem_size = 0;
  return (0);
}

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
    if (server_table.entries[i].cert.len != 0)
    {
      secure_free_charbuf(&server_table.entries[i].cert);
    }
  }

  //Free the storage allocated for the hash table
  free(server_table.entries);
  pelz_log(LOG_DEBUG, "Server Table Destroy Function Complete");
  return (0);
}

int server_table_delete(charbuf server_id)
{
  int index;

  index = 0;
  for (unsigned int i = 0; i < server_table.num_entries; i++)
  {
    if (cmp_charbuf(server_id, server_table.entries[i].server_id) == 0)
    {
      server_table.mem_size = server_table.mem_size -
        ((server_table.entries[i].cert.len * sizeof(char)) + (server_table.entries[i].server_id.len * sizeof(char)) +
        (2 * sizeof(size_t)));
      free_charbuf(&server_table.entries[i].server_id);
      secure_free_charbuf(&server_table.entries[i].cert);
      index = i + 1;
      break;
    }
  }
  if (index == 0)
  {
    pelz_log(LOG_ERR, "Server ID not found.");
    return (1);
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

int server_table_add(charbuf server_id, uint64_t handle)
{
  CertEntry tmp_entry;
  size_t max_mem_size;
  charbuf tmpcert;
  uint8_t *data;
  size_t data_size = 0;

  max_mem_size = 1000000;

  if (server_table.mem_size >= max_mem_size)
  {
    pelz_log(LOG_ERR, "Server Table memory allocation greater then specified limit.");
    return MEM_ALLOC_FAIL;
  }

  tmp_entry.server_id = new_charbuf(server_id.len);
  if (server_id.len != tmp_entry.server_id.len)
  {
    pelz_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }

  memcpy(tmp_entry.server_id.chars, server_id.chars, tmp_entry.server_id.len);
  data_size = retrieve_from_unseal_table(handle, &data);
  if (data_size == 0)
  {
    pelz_log(LOG_ERR, "Failure to retrive data from unseal table.");
    return RET_FAIL;
  }

  tmp_entry.cert = new_charbuf(data_size);
  if (data_size != tmp_entry.cert.len)
  {
    pelz_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }

  memcpy(tmp_entry.cert.chars, data, tmp_entry.cert.len);

  if (!server_table_lookup(tmp_entry.server_id, &tmpcert))
  {
    if (cmp_charbuf(tmpcert, tmp_entry.cert) == 0)
    {
      pelz_log(LOG_DEBUG, "Cert already added.");
      free_charbuf(&tmp_entry.server_id);
      secure_free_charbuf(&tmp_entry.cert);
      secure_free_charbuf(&tmpcert);
      return (0);
    }
    else
    {
      pelz_log(LOG_ERR, "Cert entry and Server ID lookup do not match.");
      free_charbuf(&tmp_entry.server_id);
      secure_free_charbuf(&tmp_entry.cert);
      secure_free_charbuf(&tmpcert);
      return NO_MATCH;
    }
  }

  CertEntry *temp;

  if ((temp = (CertEntry *) realloc(server_table.entries, (server_table.num_entries + 1) * sizeof(CertEntry))) == NULL)
  {
    pelz_log(LOG_ERR, "Cert List Space Reallocation Error");
    free_charbuf(&tmp_entry.server_id);
    secure_free_charbuf(&tmp_entry.cert);
    return ERR_REALLOC;
  }
  else
  {
    server_table.entries = temp;
  }
  server_table.entries[server_table.num_entries] = tmp_entry;
  server_table.num_entries++;
  server_table.mem_size =
    server_table.mem_size + ((tmp_entry.cert.len * sizeof(char)) + (tmp_entry.server_id.len * sizeof(char)) +
    (2 * sizeof(size_t)));
  pelz_log(LOG_INFO, "Cert Added");
  return (0);
}

int server_table_lookup(charbuf server_id, charbuf * cert)
{
  for (unsigned int i = 0; i < server_table.num_entries; i++)
  {
    if (cmp_charbuf(server_id, server_table.entries[i].server_id) == 0)
    {
      *cert = new_charbuf(server_table.entries[i].cert.len);
      if (server_table.entries[i].cert.len != cert->len)
      {
        pelz_log(LOG_ERR, "Charbuf creation error.");
        return (1);
      }
      memcpy(cert->chars, server_table.entries[i].cert.chars, cert->len);
      return (0);
    }
  }
  return (1);
}
