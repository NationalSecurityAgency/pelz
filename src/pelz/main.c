/*
 * Contains the main function used to launch the Pelz Key Service
 */

#include <stdlib.h>

#include "key_table.h"
#include "pelz_service.h"
#include "pelz_log.h"

#ifdef SGX
#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"
sgx_enclave_id_t eid = 0;
#define ENCLAVE_PATH "pelz_enclave.signed.so"
#endif

//Main function for the Pelz Service application
int main(int argc, char **argv)
{
  const int max_requests = 100;

  set_app_name("pelz");
  set_app_version("0.0.0");
  set_applog_path("/var/log/pelz.log");
  set_applog_severity_threshold(LOG_WARNING);

  int ret;
  
  #ifdef SGX
  sgx_create_enclave(ENCLAVE_PATH, 0, NULL, NULL, &eid, NULL);
  key_table_init(eid, &ret);
  #else
  //Initializing Key Table with max key entries set to key_max
  if (key_table_init())
  {
    pelz_log(LOG_ERR, "Key Table Init Failure");
    return (1);
  }
  #endif
  
  pelz_service(max_requests);

  #ifdef SGX
  key_table_destroy(eid, &ret);
  #else
  key_table_destroy();
  #endif
  return (0);
}
