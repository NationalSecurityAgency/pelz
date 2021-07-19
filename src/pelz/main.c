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
    " help          Help (displays this usage).\n"
    " wipe          Execute the Key Table Destory function.\n"
    " exit          Exit Pelz\n"

}

const struct option longopts[] = {
  {"help", no_argument, 0, 0},
  {"wipe", no_argument, 0, 0},
  {"exit", no_argument, 0, 0},
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
  char *msg = NULL;

  while ((options = getopt_long(argc, argv, "h", longopts, &option_index)) != -1)
  {
    switch (options)
    {
    case 'h':
      usage(argv[0]);
      return 0;
    case 'wipe':
      msg = "wipe";
      write_to_pipe(msg);
      break;
    case 'exit':
      msg = "exit";
      write_to_pipe(msg);
      break;
    default:
      return 1;
    }
  }
  return (0);
}
