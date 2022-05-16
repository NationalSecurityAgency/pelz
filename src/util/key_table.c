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
#include <pelz_enclave_log.h>

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED
#include "sgx_retrieve_key_impl.h"

TableResponseStatus key_table_add_key(charbuf key_id, charbuf key)
{
  Entry tmp_entry;

  if (key_table.mem_size >= MAX_MEM_SIZE)
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

TableResponseStatus key_table_add_from_handle(charbuf key_id, uint64_t handle)
{
  TableResponseStatus status;
  charbuf key;
  uint8_t *data;
  size_t data_size = 0;

  if (key_table.mem_size >= MAX_MEM_SIZE)
  {
    pelz_log(LOG_ERR, "Key Table memory allocation greater then specified limit.");
    return ERR_MEM;
  }

  data_size = retrieve_from_unseal_table(handle, &data);
  if (data_size == 0)
  {
    pelz_log(LOG_ERR, "Failure to retrieve data from unseal table.");
    return RET_FAIL;
  }

  key = new_charbuf(data_size);
  if (data_size != key.len)
  {
    pelz_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }
  memcpy(key.chars, data, key.len);

  status = key_table_add_key(key_id, key);
  return status;
}

TableResponseStatus key_table_add_from_server(charbuf key_id, charbuf server_name, int port,
  charbuf server_key_id)
{
  TableResponseStatus status;
  charbuf key;
  int index = 0;
  int ret;
  unsigned char *common_name;
  unsigned char *retrieved_key_id = NULL;
  size_t retrieved_key_id_len = 0;
  uint8_t *retrieved_key;
  size_t retrieved_key_len = 0;

  if (key_table.mem_size >= MAX_MEM_SIZE)
  {
    pelz_log(LOG_ERR, "Key Table memory allocation greater then specified limit.");
    return ERR_MEM;
  }

  if (table_lookup(SERVER, server_name, &index))
  {
    pelz_log(LOG_ERR, "Server ID not found");
    return NO_MATCH;
  }

  if (private_pkey == NULL)
  {
    pelz_log(LOG_ERR, "Private key not found");
    return NO_MATCH;
  }

  //charbuf server_name is transformed into a null terminated string common_name because the socket calls require a null terminated string
  common_name = null_terminated_string_from_charbuf(server_name);

  //the +1 is used for the len of common_name to account for the null terminater added to server_name
  ret = enclave_retrieve_key(private_pkey, server_table.entries[index].value.cert, (const char *) common_name, (server_name.len + 1), port, 
    server_key_id.chars, server_key_id.len, &retrieved_key_id, &retrieved_key_id_len, &retrieved_key, &retrieved_key_len);
  if (ret)
  {
    pelz_log(LOG_ERR, "Retrieve Key function failure");
    return RET_FAIL;
  }

  if (server_key_id.len != retrieved_key_id_len || memcmp(retrieved_key_id, server_key_id.chars, retrieved_key_id_len) != 0)
  {	
    pelz_log(LOG_ERR, "Retrieved Key Invalid Key ID");
    return RET_FAIL;
  }

  if (retrieved_key_len == 0  || retrieved_key == NULL)
  {
    pelz_log(LOG_ERR, "Retrieved Key Invalid");
    return RET_FAIL;
  }	  

  key = new_charbuf(retrieved_key_len);
  if (retrieved_key_len != key.len)
  {
    pelz_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }
  memcpy(key.chars, retrieved_key, key.len);
  status = key_table_add_key(key_id, key);
  return status;
}
