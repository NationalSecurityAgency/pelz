/*
 * key_table.c
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
#include "pelz_enclave_t.h"

TableResponseStatus key_table_add_key(charbuf key_id, charbuf key)
{
  Entry tmp_entry;
  size_t max_mem_size;
  charbuf tmpkey;
  int index = 0;

  max_mem_size = 1000000;

  if (key_table.mem_size >= max_mem_size)
  {
    pelz_log(LOG_ERR, "Key Table memory allocation greater then specified limit.");
    return ERR_MEM;
  }

  tmp_entry.id = copy_chars_from_charbuf(key_id, 0);
  tmp_entry.value.key = copy_chars_from_charbuf(key, 0);

  if (table_lookup(KEY, tmp_entry.id, &index) == 0)
  {
    tmpkey = copy_chars_from_charbuf(key_table.entries[index].value.key, 0);
    if (cmp_charbuf(tmpkey, tmp_entry.value.key) == 0)
    {
      pelz_log(LOG_DEBUG, "Key already added.");
      free_charbuf(&tmp_entry.id);
      secure_free_charbuf(&tmp_entry.value.key);
      secure_free_charbuf(&tmpkey);
      return OK;                //Review add key flow and check if code is necessary
    }
    else
    {
      pelz_log(LOG_ERR, "Key entry and Key ID lookup do not match.");
      free_charbuf(&tmp_entry.id);
      secure_free_charbuf(&tmp_entry.value.key);
      secure_free_charbuf(&tmpkey);
      return NO_MATCH;
    }
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

TableResponseStatus key_table_add_from_server(charbuf key_id, charbuf server, charbuf port)
{
  Entry tmp_entry;
  size_t max_mem_size;
  charbuf tmpkey;
  int index = 0;

  max_mem_size = 1000000;

  if (key_table.mem_size >= max_mem_size)
  {
    pelz_log(LOG_ERR, "Key Table memory allocation greater then specified limit.");
    return ERR_MEM;
  }

  tmp_entry.id = copy_chars_from_charbuf(key_id, 0);

  //Code for retieve key

  if (table_lookup(KEY, tmp_entry.id, &index) == 0)
  {
    tmpkey = copy_chars_from_charbuf(key_table.entries[index].value.key, 0);
    if (cmp_charbuf(tmpkey, tmp_entry.value.key) == 0)
    {
      pelz_log(LOG_DEBUG, "Key already added.");
      free_charbuf(&tmp_entry.id);
      secure_free_charbuf(&tmp_entry.value.key);
      secure_free_charbuf(&tmpkey);
      return OK;                //Review add key flow and check if code is necessary
    }
    else
    {
      pelz_log(LOG_ERR, "Key entry and Key ID lookup do not match.");
      free_charbuf(&tmp_entry.id);
      secure_free_charbuf(&tmp_entry.value.key);
      secure_free_charbuf(&tmpkey);
      return NO_MATCH;
    }
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
