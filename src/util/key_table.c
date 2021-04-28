/*
 * key_table.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pelz_io.h"
#include <key_table.h>
#include <util.h>
#include <pelz_request_handler.h>
#include <CharBuf.h>
#include <pelz_log.h>

KeyTable key_table;

//Initialize key table
int key_table_init(void)
{
  if ((key_table.entries = (KeyEntry *) malloc(sizeof(KeyEntry))) == NULL)
  {
    pelz_log(LOG_ERR, "Key List Space Allocation Error");
    return (1);
  }

  key_table.num_entries = 0;
  key_table.mem_size = 0;
  return (0);
}

//Destroy key table
int key_table_destroy(void)
{
  pelz_log(LOG_DEBUG, "Key Table Destroy Function Starting");
  if (key_table.num_entries >= 0)
  {
    for (int i = 0; i < key_table.num_entries; i++)
    {
      if (key_table.entries[i].key_id.len != 0)
      {
        freeCharBuf(&key_table.entries[i].key_id);
      }
      if (key_table.entries[i].key.len != 0)
      {
        secureFreeCharBuf(&key_table.entries[i].key);
      }
    }
  }
  else
  {
    pelz_log(LOG_ERR, "Destroy Table Error");
    return (1);
  }

  //Free the storage allocated for the hash table
  free(key_table.entries);
  pelz_log(LOG_DEBUG, "Key Table Destroy Function Complete");
  return (0);
}

int key_table_delete(CharBuf key_id)
{
  int index;

  index = 0;
  for (int i = 0; i < key_table.num_entries; i++)
  {
    if (cmpCharBuf(key_id, key_table.entries[i].key_id) == 0)
    {
      key_table.mem_size = key_table.mem_size -
        ((key_table.entries[i].key.len * sizeof(char)) + (key_table.entries[i].key_id.len * sizeof(char)) +
        (2 * sizeof(size_t)));
      freeCharBuf(&key_table.entries[i].key_id);
      secureFreeCharBuf(&key_table.entries[i].key);
      index = i + 1;
      break;
    }
  }
  if (index == 0)
  {
    pelz_log(LOG_ERR, "Key ID not found.");
    return (1);
  }
  else
  {
    for (int i = index; i < key_table.num_entries; i++)
    {
      key_table.entries[i - 1] = key_table.entries[i];
    }
    key_table.num_entries -= 1;
    if ((key_table.entries = (KeyEntry *) realloc(key_table.entries, (key_table.num_entries) * sizeof(KeyEntry))) == NULL)
    {
      pelz_log(LOG_ERR, "Key List Space Reallocation Error");
      return (1);
    }
  }
  return (0);
}

int key_table_add(CharBuf key_id, CharBuf * key)
{
  KeyEntry tmp_entry;
  size_t max_mem_size;
  CharBuf tmpkey;

  max_mem_size = 1000000;

  if (key_table.mem_size >= max_mem_size)
  {
    pelz_log(LOG_ERR, "Key Table memory allocation greater then specified limit.");
    return (1);
  }

  tmp_entry.key_id = newCharBuf(key_id.len);
  memcpy(tmp_entry.key_id.chars, key_id.chars, tmp_entry.key_id.len);

  if (key_load(&tmp_entry))
  {
    //If the code cannot retrieve the key from the URI provided by the Key ID, then we error out of the function before touching the Key Table.
    freeCharBuf(&tmp_entry.key_id);
    return (1);
  }

  if (!key_table_lookup(tmp_entry.key_id, &tmpkey))
  {
    if (cmpCharBuf(tmpkey, tmp_entry.key) == 0)
    {
      pelz_log(LOG_DEBUG, "Key already added.");
      *key = copyBytesFromBuf(tmpkey, 0);
      freeCharBuf(&tmp_entry.key_id);
      secureFreeCharBuf(&tmp_entry.key);
      secureFreeCharBuf(&tmpkey);
      return (0);
    }
    else
    {
      pelz_log(LOG_ERR, "Key entry and Key ID lookup do not match.");
      freeCharBuf(&tmp_entry.key_id);
      secureFreeCharBuf(&tmp_entry.key);
      secureFreeCharBuf(&tmpkey);
      return (1);
    }
  }

  if ((key_table.entries = (KeyEntry *) realloc(key_table.entries, (key_table.num_entries + 1) * sizeof(KeyEntry))) == NULL)
  {
    pelz_log(LOG_ERR, "Key List Space Reallocation Error");
    freeCharBuf(&tmp_entry.key_id);
    secureFreeCharBuf(&tmp_entry.key);
    return (1);
  }
  key_table.entries[key_table.num_entries] = tmp_entry;
  key_table.num_entries++;
  key_table.mem_size =
    key_table.mem_size + ((tmp_entry.key.len * sizeof(char)) + (tmp_entry.key_id.len * sizeof(char)) + (2 * sizeof(size_t)));
  pelz_log(LOG_INFO, "Key Added");
  *key = copyBytesFromBuf(tmp_entry.key, 0);
  return (0);
}

int key_table_lookup(CharBuf key_id, CharBuf * key)
{
  for (int i = 0; i < key_table.num_entries; i++)
  {
    if (cmpCharBuf(key_id, key_table.entries[i].key_id) == 0)
    {
      *key = newCharBuf(key_table.entries[i].key.len);
      memcpy(key->chars, key_table.entries[i].key.chars, key->len);
      return (0);
    }
  }
  return (1);
}