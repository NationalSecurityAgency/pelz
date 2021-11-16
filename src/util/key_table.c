/*
 * key_table.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pelz_io.h>
#include <common_table.h>
#include <key_table.h>
#include <util.h>
#include <pelz_request_handler.h>
#include <charbuf.h>
#include <pelz_log.h>

#include "sgx_trts.h"
#include "pelz_enclave_t.h"

int key_table_add(charbuf key_id, charbuf * key)
{
  Entry tmp_entry;
  size_t max_mem_size;
  charbuf tmpkey;
  int index = 0;

  max_mem_size = 1000000;

  if (key_table.mem_size >= max_mem_size)
  {
    pelz_log(LOG_ERR, "Key Table memory allocation greater then specified limit.");
    return (1);
  }

  tmp_entry.id = new_charbuf(key_id.len);
  memcpy(tmp_entry.id.chars, key_id.chars, tmp_entry.id.len);

  int ret;
  size_t ocall_key_len = 0;
  unsigned char *ocall_key_data = NULL;

  key_load(&ret, tmp_entry.id.len, tmp_entry.id.chars, &ocall_key_len, &ocall_key_data);
  if (!sgx_is_outside_enclave(ocall_key_data, ocall_key_len))
  {
    free_charbuf(&tmp_entry.id);
    return (1);
  }
  tmp_entry.value.key.len = ocall_key_len;
  tmp_entry.value.key.chars = (unsigned char *) malloc(ocall_key_len);
  memcpy(tmp_entry.value.key.chars, ocall_key_data, ocall_key_len);
  if (!sgx_is_outside_enclave(ocall_key_data, ocall_key_len))
  {
    ret = 1;
  }
  else
  {
    ocall_free(ocall_key_data, ocall_key_len);
  }

  if (ret)
  {
    //If the code cannot retrieve the key from the URI provided by the Key ID, then we error out of the function before touching the Key Table.
    free_charbuf(&tmp_entry.id);
    return (1);
  }

  if (table_lookup(KEY, tmp_entry.id, &index) == 0)
  {
    tmpkey = new_charbuf(key_table.entries[index].value.key.len);
    if (key_table.entries[index].value.key.len != tmpkey.len)
    {
      pelz_log(LOG_ERR, "Charbuf creation error.");
      return (1);
    }
    memcpy(tmpkey.chars, key_table.entries[index].value.key.chars, tmpkey.len);
    if (cmp_charbuf(tmpkey, tmp_entry.value.key) == 0)
    {
      pelz_log(LOG_DEBUG, "Key already added.");
      *key = copy_chars_from_charbuf(tmpkey, 0);
      free_charbuf(&tmp_entry.id);
      secure_free_charbuf(&tmp_entry.value.key);
      secure_free_charbuf(&tmpkey);
      return (0);
    }
    else
    {
      pelz_log(LOG_ERR, "Key entry and Key ID lookup do not match.");
      free_charbuf(&tmp_entry.id);
      secure_free_charbuf(&tmp_entry.value.key);
      secure_free_charbuf(&tmpkey);
      return (1);
    }
  }

  Entry *temp;

  if ((temp = (Entry *) realloc(key_table.entries, (key_table.num_entries + 1) * sizeof(Entry))) == NULL)
  {
    pelz_log(LOG_ERR, "Key List Space Reallocation Error");
    free_charbuf(&tmp_entry.id);
    secure_free_charbuf(&tmp_entry.value.key);
    return (1);
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
  *key = copy_chars_from_charbuf(tmp_entry.value.key, 0);
  return (0);
}
