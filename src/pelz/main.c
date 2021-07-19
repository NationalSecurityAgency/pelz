/*
 * Contains the main function used to launch the Pelz Key Service
 */

#include <getopt.h>
#include <stdlib.h>

#include "pelz_log.h"
#include "pelz_io.h"

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"
sgx_enclave_id_t eid = 0;

#define ENCLAVE_PATH "sgx/pelz_enclave.signed.so"

static void usage(const char *prog)
{
  fprintf(stdout,
    "usage: %s [options] \n\n"
    "options are: \n\n"
    " -h or --help  Help (displays this usage).\n"
    " -w or --wipe        Execute the Key Table Destory function.\n"
    " -e or --exit        Exit Pelz\n", prog);
}

const struct option longopts[] = {
  {"help", no_argument, 0, 'h'},
  {"wipe", no_argument, 0, 'w'},
  {"exit", no_argument, 0, 'e'},
  {0, 0, 0, 0}
};

//Main function for the Pelz Service application
int main(int argc, char **argv)
{
  set_app_name("pelz");
  set_app_version("0.0.0");
  set_applog_max_msg_len(1024);
  set_applog_path("/var/log/pelz.log");
  set_applog_severity_threshold(LOG_WARNING);

  int options;
  int option_index;
  char msg[4];

  while ((options = getopt_long(argc, argv, "hwe", longopts, &option_index)) != -1)
  {
    switch (options)
    {
    case 'h':
      usage(argv[0]);
      return 0;
    case 'w':
      memcpy(msg, "wipe", 4);
      write_to_pipe(msg);
      break;
    case 'e':
      memcpy(msg, "exit", 4);
      write_to_pipe(msg);
      return 0;
    default:
      return 1;
    }
  }
  return (0);
}
