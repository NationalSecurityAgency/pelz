/*
 * server_table.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pelz_io.h>
#include <common_table.h>
#include <server_table.h>
#include <util.h>
#include <pelz_request_handler.h>
#include <charbuf.h>
#include <pelz_log.h>

#include "sgx_trts.h"
#include "pelz_enclave_t.h"
#include "kmyth_enclave.h"

int server_table_add(charbuf server_id, uint64_t handle)
{
  CertEntry tmp_entry;
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

  tmp_entry.cert = new_charbuf(data_size);
  if (data_size != tmp_entry.cert.len)
  {
    pelz_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }

  memcpy(tmp_entry.cert.chars, data, tmp_entry.cert.len);

  if (table_lookup(SERVER, tmp_entry.id, &index) == 0)
  {
    tmpcert = new_charbuf(server_table.entries[index].cert.len);
    if (server_table.entries[index].cert.len != tmpcert.len)
    {
      pelz_log(LOG_ERR, "Charbuf creation error.");
      return (1);
    }
    memcpy(tmpcert.chars, server_table.entries[index].cert.chars, tmpcert.len);
    if (cmp_charbuf(tmpcert, tmp_entry.cert) == 0)
    {
      pelz_log(LOG_DEBUG, "Cert already added.");
      free_charbuf(&tmp_entry.id);
      secure_free_charbuf(&tmp_entry.cert);
      secure_free_charbuf(&tmpcert);
      return (0);
    }
    else
    {
      pelz_log(LOG_ERR, "Cert entry and Server ID lookup do not match.");
      free_charbuf(&tmp_entry.id);
      secure_free_charbuf(&tmp_entry.cert);
      secure_free_charbuf(&tmpcert);
      return NO_MATCH;
    }
  }

  CertEntry *temp;

  if ((temp = (CertEntry *) realloc(server_table.entries, (server_table.num_entries + 1) * sizeof(CertEntry))) == NULL)
  {
    pelz_log(LOG_ERR, "Cert List Space Reallocation Error");
    free_charbuf(&tmp_entry.id);
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
    server_table.mem_size + ((tmp_entry.cert.len * sizeof(char)) + (tmp_entry.id.len * sizeof(char)) + (2 * sizeof(size_t)));
  pelz_log(LOG_INFO, "Cert Added");
  return (0);
}
