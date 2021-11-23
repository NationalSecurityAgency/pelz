/*
 * key_table.c
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
#include "sgx_retrieve_key_impl.h"

TableResponseStatus key_table_add_key(charbuf key_id, charbuf key)
{
  Entry tmp_entry;
  size_t max_mem_size;

  max_mem_size = 1000000;

  if (key_table.mem_size >= max_mem_size)
  {
    pelz_log(LOG_ERR, "Key Table memory allocation greater then specified limit.");
    return ERR_MEM;
  }

  tmp_entry.id = copy_chars_from_charbuf(key_id, 0);
  tmp_entry.value.key = copy_chars_from_charbuf(key, 0);

  Entry *temp;

  if ((temp = (Entry *) realloc(key_table.entries, (key_table.num_entries + 1) * sizeof(Entry))) == NULL)
  {
    pelz_log(LOG_ERR, "Key List Space Reallocation Error");
    free_charbuf(&tmp_entry.id);
    secure_free_charbuf(&tmp_entry.value.key);
    return ERR_REALLOC;
  }
  else
  {
    key_table.entries = temp;
  }

  key_table.entries[key_table.num_entries] = tmp_entry;
  key_table.num_entries++;
  key_table.mem_size =
    key_table.mem_size + ((tmp_entry.value.key.len * sizeof(char)) + (tmp_entry.id.len * sizeof(char)) + (2 * sizeof(size_t)));
  pelz_log(LOG_INFO, "Key Added");
  return OK;
}

TableResponseStatus key_table_add_from_server(charbuf key_id, charbuf server_id, charbuf server_key_id)
{
  Entry tmp_entry;
  size_t max_mem_size;
  int index = 0;
  int ret;

  max_mem_size = 1000000;

  if (key_table.mem_size >= max_mem_size)
  {
    pelz_log(LOG_ERR, "Key Table memory allocation greater then specified limit.");
    return ERR_MEM;
  }

  tmp_entry.id = copy_chars_from_charbuf(key_id, 0);

  if (table_lookup(SERVER, server_id, &index))
  {
    pelz_log(LOG_ERR, "Server ID not found");
    return ERR;
  }

  ret = enclave_retrieve_key(private_pkey, server_table.entries[index].value.cert);
  if (ret)
  {
    pelz_log(LOG_ERR, "Retrieve Key function failure");
    return ERR;
  }

  Entry *temp;

  if ((temp = (Entry *) realloc(key_table.entries, (key_table.num_entries + 1) * sizeof(Entry))) == NULL)
  {
    pelz_log(LOG_ERR, "Key List Space Reallocation Error");
    free_charbuf(&tmp_entry.id);
    secure_free_charbuf(&tmp_entry.value.key);
    return ERR_REALLOC;
  }
  else
  {
    key_table.entries = temp;
  }

  key_table.entries[key_table.num_entries] = tmp_entry;
  key_table.num_entries++;
  key_table.mem_size =
    key_table.mem_size + ((tmp_entry.value.key.len * sizeof(char)) + (tmp_entry.id.len * sizeof(char)) + (2 * sizeof(size_t)));
  pelz_log(LOG_INFO, "Key Added");
  return OK;
}
