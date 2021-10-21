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

KeyTable key_table = {
  .entries = NULL,
  .num_entries = 0,
  .mem_size = 0
};

ServerTable server_table = {
  .entries = NULL,
  .num_entries = 0,
  .mem_size = 0
};

//Destroy server table
int table_destroy(int type)
{
  KeyTable table;

  pelz_log(LOG_DEBUG, "Table Destroy Function Starting");

  switch (type)
  {
  case KEY:
    KeyTable table;
    table = key_table;
    break;
  case SERVER:
    ServerTable table2;
    table2 = server_table;
    break;
  default:
    return (1);
  }

  for (unsigned int i = 0; i < table.num_entries; i++)
  {
    if (table.entries[i].id.len != 0)
    {
      free_charbuf(table->entries[i]->id);
    }
    if (type == KEY)
    {
      if (table.entries[i].key.len != 0)
      {
        secure_free_charbuf(table->entries[i]->key);
      }
    }
    if (type == SERVER)
    {
      if (table.entries[i].cert.len != 0)
      {
        secure_free_charbuf(table->entries[i]->cert);
      }
    }
  }

  //Free the storage allocated for the hash table
  free(table->entries);
  table.entries = NULL;
  table.num_entries = 0;
  table.mem_size = 0;

  pelz_log(LOG_DEBUG, "Table Destroy Function Complete");
  return (0);
}

int table_delete(int type, charbuf id)
{
  int index = 0;

  switch (type)
  {
  case KEY:
    for (unsigned int i = 0; i < key_table.num_entries; i++)
    {
      if (cmp_charbuf(id, key_table.entries[i].id) == 0)
      {
        key_table.mem_size = key_table.mem_size -
          ((key_table.entries[i].key.len * sizeof(char)) + (key_table.entries[i].id.len * sizeof(char)) + (2 * sizeof(size_t)));
        free_charbuf(&key_table.entries[i].id);
        secure_free_charbuf(&key_table.entries[i].key);
        index = i + 1;
        break;
      }
    }
    if (index == 0)
    {
      pelz_log(LOG_ERR, "Key ID not found.");
      return (1);
    }
    else if (key_table.mem_size == 0)
    {
      free(key_table.entries);
      key_table.entries = NULL;
      key_table.num_entries = 0;
    }
    else
    {
      for (unsigned int i = index; key_table.num_entries; i++)
      {
        key_table.entries[i - 1] = key_table.entries[i];
      }
      key_table.num_entries -= 1;

      KeyEntry *temp;

      if ((temp = (KeyEntry *) realloc(key_table.entries, (key_table.num_entries) * sizeof(KeyEntry))) == NULL)
      {
        pelz_log(LOG_ERR, "Key List Space Reallocation Error");
        return (1);
      }
      else
      {
        key_table.entries = temp;
      }
    }
    break;
  case SERVER:
    for (unsigned int i = 0; i < server_table.num_entries; i++)
    {
      if (cmp_charbuf(id, server_table.entries[i].id) == 0)
      {
        server_table.mem_size = server_table.mem_size -
          ((server_table.entries[i].cert.len * sizeof(char)) + (server_table.entries[i].id.len * sizeof(char)) +
          (2 * sizeof(size_t)));
        free_charbuf(&server_table.entries[i].id);
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
    break;
  default:
    return (1);
  }
  return (0);
}

int table_lookup(int type, charbuf id, int *index)
{
  switch (type)
  {
  case KEY:
    for (unsigned int i = 0; i < server_table.num_entries; i++)
    {
      if (cmp_charbuf(id, key_table.entries[i].id) == 0)
      {
        *index = i;
        return (0);
      }
    }
    return (1);
  case SERVER:
    for (unsigned int i = 0; i < server_table.num_entries; i++)
    {
      if (cmp_charbuf(id, server_table.entries[i].id) == 0)
      {
        *index = i;
        return (0);
      }
    }
    return (1);
  default:
    return (1);
  }
}
