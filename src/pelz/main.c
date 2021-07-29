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
    "usage: %s <keywords> [options] \n\n"
    "keywords are: \n\n"
    "-d or --debug                   Enable debug messaging and logging.\n"
    "-h or --help                    Help (displays this usage).\n\n"
    "exit                            Terminate running pelz-service\n\n"
    "load <type> <path>              Loads a value of type <type> (currently either cert or private)\n"
    "                                into the pelz-service enclave. These files must be formatted as\n"
    "                                a .ski or .nkl file.\n"
    "load cert <path/to/file>        Loads a server certificate into the pelz-service enclave\n"
    "load private <path/to/file>     Loads a private key for connections to key servers into the\n"
    "                                pelz-service enclave. This will fail if a key is already\n"
    "                                loaded.\n\n"
    "remove <target> <id> [options]  Removes a value of type <target> (currently either cert or key)\n"
    "                                from memory within the pelz-service enclave. The -a option may\n"
    "                                be used to drop all server certificates or all keys.\n"
    "remove key <id> [options]       Removes a key with a specified id from the pelz-service enclave if it\n"
    "                                exists. If -a is given, no id is required.\n"
    "remove cert <path> [options]    Removes the server cert at the specified path from the pelz-service\n"
    "                                loaded certificates. If -a is given, no path is required.\n"
    "-a or --all                     Used only with remove to indicate removing all server certificates or\n"
    "                                keys from the pelz-service key table.\n\n"
    "seal <path> [options]           Seals the input file to the pelz-service enclave. This creates a .nkl\n"
    "                                file. This can also be used in conjunction with the TPM to double\n"
    "                                seal a file and create a .ski file as output.\n"
    "-t or --tpm                     Use the TPM as well when sealing. This requires the TPM to be enabled.\n"
    "-o or --output <output path>    By default, seal will output a new file with the same name but the\n"
    "                                .nkl extension. Using -o allows the user to specify their output\n"
    "                                file destination.\n", prog);
}

const struct option longopts[] = {
  {"help", no_argument, 0, 'h'},
  {"debug", no_argument, 0, 'd'},
  {"exit", no_argument, 0, 0},
  {"load", no_argument, 0, 0},
  {"remove", no_argument, 0, 0},
  {"seal", no_argument, 0, 0},
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

  while ((options = getopt_long_only(argc, argv, "h", longopts, &option_index)) != -1)
  {
    switch (options)
    {
    case 'h':
      usage(argv[0]);
      return 0;
    case 'd':
      set_applog_severity_threshold(LOG_DEBUG);
      set_applog_output_mode(0);
      break;
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
    usage(argv[0]);
  
  return (0);
}
