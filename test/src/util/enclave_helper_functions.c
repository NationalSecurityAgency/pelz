/*
 * enclave_helper_functions.c
 */

#include "common_table.h"
#include "charbuf.h"

#include "sgx_trts.h"
#include "pelz_enclave_t.h"

TableResponseStatus test_table_lookup(TableType type, charbuf id, int *index)
{
  return (table_lookup(type, id, index));
}
