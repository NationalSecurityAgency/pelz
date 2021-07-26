/*
 * Contains the main function used to launch the Pelz Key Service
 */

#include <getopt.h>
#include <stdlib.h>

#include "pelz_log.h"
#include "pelz_io.h"

#include "pelz_enclave.h"
sgx_enclave_id_t eid = 0;

static void usage(const char *prog)
{
  fprintf(stdout,
    "usage: %s [options] \n\n"
    "options are: \n\n"
    " -h or --help        Help (displays this usage).\n"
    " -t or --table       Execute the Key Table Destory function.\n"
    " -w or --wipe        Delete the Key ID provided.\n"
    " -e or --exit        Exit Pelz\n", prog);
}

const struct option longopts[] = {
  {"help", no_argument, 0, 'h'},
  {"table", no_argument, 0, 't'},
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
  char *msg;

  while ((options = getopt_long_only(argc, argv, "htw:e", longopts, &option_index)) != -1)
  {
    switch (options)
    {
    case 'h':
      usage(argv[0]);
      return 0;
    case 't':
      msg = (char *) calloc(8, sizeof(char));
      memcpy(msg, "pelz -t", 7);
      write_to_pipe(msg);
      free(msg);
      break;
    case 'w':
      msg = (char *) calloc((9 + strlen(optarg)), sizeof(char));
      memcpy(msg, "pelz -w ", 8);
      memcpy(&msg[8], optarg, strlen(optarg));
      write_to_pipe(msg);
      free(msg);
      return 0;
    case 'e':
      msg = (char *) calloc(8, sizeof(char));
      memcpy(msg, "pelz -e", 7);
      write_to_pipe(msg);
      free(msg);
      return 0;
    default:
      return 1;
    }
  }

  if (optind == 1 )
  {
    printf("No options were passed");
    usage(argv[0]);
  }
  return (0);
}
