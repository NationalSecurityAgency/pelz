/*
 * Contains the main function used to launch the Pelz Key Service
 */

#include <getopt.h>
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

static void usage(const char *prog)
{
  fprintf(stdout,
    "\nusage: %s [options] \n\n"
    "options are: \n\n"
    " -h or --help          Help (displays this usage).\n"
    " -m or --max_requests  Maximum number of sockets pelz can make available at any given time, default: 100\n"
    " -v or --verbose       Enable detailed logging.\n", prog);
}

const struct option longopts[] = {
  {"help", no_argument, 0, 'h'},
  {"max_requests", required_argument, 0, 'm'},
  {"verbose", no_argument, 0, 'v'},
  {0, 0, 0, 0}
};

//Main function for the Pelz Service application
int main(int argc, char **argv)
{
  if (argc == 1)
  {
    usage(argv[0]);
    return 0;
  }

  set_app_name("pelz");
  set_app_version("0.0.0");
  set_applog_path("/var/log/pelz.log");
  set_applog_severity_threshold(LOG_WARNING);

  int max_requests = 100;
  int options;
  int option_index;
  long mr = 0;

  while ((options = getopt_long(argc, argv, "m:hv", longopts, &option_index)) != -1)
  {
    switch (options)
    {
    case 'h':
      usage(argv[0]);
      return 0;
    case 'm':
      if (optarg && (mr = atol(optarg)) > 0)
      {
        max_requests = (int) mr;
        break;
      }
      else
      {
        pelz_log(LOG_ERR, "max_request must be an integer. Received invalid option '%s'", optarg);
        return 1;
      }
    case 'v':
      set_applog_severity_threshold(LOG_DEBUG);
      set_applog_output_mode(0);
      break;
    default:
      return 1;
    }
  }
  
  #ifdef SGX
  int ret;
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
  
  pelz_service((const int) max_requests);

  #ifdef SGX
  key_table_destroy(eid, &ret);
  #else
  key_table_destroy();
  #endif
  return (0);
}
