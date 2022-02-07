/*
 * common_table.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pelz_io.h>
#include <common_table.h>
#include <util.h>
#include <pelz_request_handler.h>
#include <charbuf.h>
#include <pelz_log.h>

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED
#include "kmyth_enclave_trusted.h"

Table key_table = {
  .entries = NULL,
  .num_entries = 0,
  .mem_size = 0
};

Table server_table = {
  .entries = NULL,
  .num_entries = 0,
  .mem_size = 0
};

//Destroy server table
TableResponseStatus table_destroy(TableType type)
{
  Table *table;

  pelz_log(LOG_DEBUG, "Table Destroy Function Starting");

  switch (type)
  {
  case KEY:
    table = &key_table;
    break;
  case SERVER:
    table = &server_table;
    break;
  default:
    return ERR;
  }

  for (unsigned int i = 0; i < table->num_entries; i++)
  {
    if (table->entries[i].id.len != 0)
    {
      free_charbuf(&table->entries[i].id);
    }
    if (type == KEY)
    {
      if (table->entries[i].value.key.len != 0)
      {
        secure_free_charbuf(&table->entries[i].value.key);
      }
    }
    if (type == SERVER)
    {
      X509_free(table->entries[i].value.cert);
    }
  }

  //Free the storage allocated for the hash table
  free(table->entries);
  table->entries = NULL;
  table->num_entries = 0;
  table->mem_size = 0;

  pelz_log(LOG_DEBUG, "Table Destroy Function Complete");
  return OK;
}

TableResponseStatus table_delete(TableType type, charbuf id)
{
  Table *table;
  int index = 0;
  int data_size = 0;

  switch (type)
  {
  case KEY:
    table = &key_table;
    break;
  case SERVER:
    table = &server_table;
    break;
  default:
    return ERR;
  }

  for (unsigned int i = 0; i < table->num_entries; i++)
  {
    if (cmp_charbuf(id, table->entries[i].id) == 0)
    {
      if (type == KEY)
      {
        table->mem_size =
          table->mem_size - ((table->entries[i].value.key.len * sizeof(char)) + (table->entries[i].id.len * sizeof(char)) +
          (2 * sizeof(size_t)));
      }
      else if (type == SERVER)
      {
        data_size = i2d_X509(table->entries[i].value.cert, NULL);
        table->mem_size = table->mem_size - ((table->entries[i].id.len * sizeof(char)) + sizeof(size_t) + data_size);
      }
      free_charbuf(&table->entries[i].id);
      if (type == KEY)
      {
        secure_free_charbuf(&table->entries[i].value.key);
      }
      if (type == SERVER)
      {
        X509_free(table->entries[i].value.cert);
      }
      index = i + 1;
      break;
    }
  }
  if (index == 0)
  {
    pelz_log(LOG_ERR, "ID not found.");
    return NO_MATCH;
  }
  else if (table->mem_size == 0)
  {
    free(table->entries);
    table->entries = NULL;
    table->num_entries = 0;
  }
  else
  {
    for (unsigned int i = index; i < table->num_entries; i++)
    {
      table->entries[i - 1] = table->entries[i];
    }
    table->num_entries -= 1;

    Entry *temp;

    if ((temp = (Entry *) realloc(table->entries, (table->num_entries) * sizeof(Entry))) == NULL)
    {
      pelz_log(LOG_ERR, "List Space Reallocation Error");
      return ERR_REALLOC;
    }
    else
    {
      table->entries = temp;
    }
  }
  return OK;
}

TableResponseStatus table_lookup(TableType type, charbuf id, int *index)
{
  Table *table;

  switch (type)
  {
  case KEY:
    table = &key_table;
    break;
  case SERVER:
    table = &server_table;
    break;
  default:
    return ERR;
  }

  for (unsigned int i = 0; i < table->num_entries; i++)
  {
    if (cmp_charbuf(id, table->entries[i].id) == 0)
    {
      *index = i;
      return OK;
    }
  }
  return NO_MATCH;
}
