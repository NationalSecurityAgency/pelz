/*
 * Contains the main function used to launch the Pelz Key Service
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <kmyth/kmyth.h>
#include <kmyth/file_io.h>

#include "pelz_log.h"
#include "pelz_io.h"
#include "charbuf.h"
#include "seal.h"
#include "cmd_interface.h"

#include "pelz_enclave.h"
#include "sgx_seal_unseal_impl.h"

sgx_enclave_id_t eid = 0;

#define BUFSIZE 1024
#define MODE 0600

static void pki_usage()
{
  fprintf(stdout,
    "pki commands:\n\n"
    "  pki <action> <type> <path>        This is used to load or remove certificates and keys used for\n"
    "                                    communicating with key servers.\n\n"
    "  pki load <type> <path>            Loads a client's private key or server's public certificate into\n"
    "                                    the pelz-service enclave. These files must be sealed by the\n"
    "                                    enclave prior to loading. The load command only accepts .nkl or\n"
    "                                    .ski files. Additionally, the original keys and certs must be\n"
    "                                    in the DER format prior to sealing.\n\n"
    "  pki load cert <path/to/file>      Loads a server certificate into the pelz-service enclave\n\n"
    "  pki load private <path/to/file>   Loads a private key for connections to key servers into the\n"
    "                                    pelz-service enclave. This will fail if a private key is already\n"
    "                                    loaded.\n\n"
    "  pki cert list                     Provides the Common Names of the certificates currently loaded\n"
    "                                    in the pelz-service.\n\n"
    "  pki remove <CN|private>           Removes the server certificate with Common Name (CN) from the\n"
    "                                    pelz-service. If the 'private' keyword is used, the private key\n"
    "                                    will be removed from the pelz-service.\n\n"
    "    -a, --all                       If -a or --all is selected, all server certificates will be\n"
    "                                    removed. The private key will not be removed.\n");
}

static void ca_usage()
{
  fprintf(stdout,
    "ca commands:\n\n"
    "  ca <action> <value>               These commands load or remove CA certificates\n"
    "                                    used to validate signed requests.\n\n"
    "  ca load <path/to/file>            Loads a sealed CA certificate into the pelz-service enclave.\n"
    "                                    The certificate must be in .der.nkl or .der.ski format.\n\n"
    "  ca list                           Lists the Common Names of all CA certificates currently loaded\n"
    "                                    in the pelz-service.\n\n"
    "  ca remove <CN>                    Removes the CA certificate with Common Name (CN) from the pelz-service.\n\n"
    "    -a, --all                       If -a or --all is selected, all CA certificates will be removed.\n\n");
}

static void keytable_usage()
{
  fprintf(stdout,
    "keytable commands:\n\n"
    "  keytable remove <id>              Removes a data key from the pelz-service enclave's key table.\n\n"
    "    -a, --all                       If -a or --all is selected, all keys in the key table will be\n"
    "                                    removed.\n\n"
    "  keytable list                     Lists the keys currently loaded by their id. This command does\n"
    "                                    not provide the actual key values of keys within the key table.\n");
}

static void seal_usage()
{
  fprintf(stdout,
    "seal <path> [options]               Seals the input file to the pelz-service enclave. This creates\n"
    "                                    a .nkl file.\n\n"
    "  -t or --tpm                       Use the TPM along with the enclave when sealing. The TPM must\n"
    "                                    be enabled. If the TPM is used in conjunction with the enclave,\n"
    "                                    the .nkl file contents will be sealed and output as a .ski file.\n\n"
    "  -o or --output <output path>      Seal defaults to outputting a new file with the same name as the\n"
    "                                    input file, but with a .nkl or .ski extension appended. Using\n"
    "                                    the -o option allows the user to specify the output file name.\n");
}

static void usage(const char *prog)
{
  fprintf(stdout,
    "usage: %s <keywords> [options] \n\n"
    "keywords and options are: \n\n"
    "options:\n"
    "  -d or --debug                     Enable debug messaging and logging.\n"
    "  -h or --help                      Help (displays this usage).\n\n"
    "exit                                Terminate running pelz-service\n\n", prog);
  seal_usage();
  fprintf(stdout, "\n");
  pki_usage();
  fprintf(stdout, "\n");
  keytable_usage();
  fprintf(stdout, "\n");
  ca_usage();
  fprintf(stdout, "\n");
}

const struct option longopts[] = {
  {"help", no_argument, 0, 'h'},
  {"debug", no_argument, 0, 'd'},
  {"tpm", no_argument, 0, 't'},
  {"output", required_argument, 0, 'o'},
  {"all", no_argument, 0, 'a'},
  {0, 0, 0, 0}
};

//Main function for the pelz command interface application
int main(int argc, char **argv)
{
  set_app_name("pelz");
  set_app_version("0.0.0");
  set_applog_max_msg_len(1024);
  set_applog_path("/var/log/pelz.log");
  set_applog_severity_threshold(LOG_INFO);
  set_applog_output_mode(0);

  int options;
  int option_index;
  int arg_index = 0;
  int cmd = -1;
  int cmd_param_index = 0;  // index in argv of the first non-keyword command parameter
  CmdArgValue cmd_arg[5] = { EMPTY, EMPTY, EMPTY, EMPTY, EMPTY };
  bool all = false;
  bool tpm = false;
  bool out = false;
  char *outPath = NULL;
  size_t outPath_size = 0;

  if (argc == 1)
  {
    usage(argv[0]);
    return 0;
  }

  //While function to go thru options from command line
  while ((options = getopt_long(argc, argv, "hdato:", longopts, &option_index)) != -1)
  {
    switch (options)
    {
    case 'h':
      usage(argv[0]);
      return 0;
    case 'd':
      set_applog_severity_threshold(LOG_DEBUG);
      arg_index = arg_index + 1;
      break;
    case 't':
      tpm = true;
      arg_index = arg_index + 1;
      break;
    case 'a':
      all = true;
      arg_index = arg_index + 1;
      break;
    case 'o':      
      out = true;
      outPath_size = strlen(optarg) + 1;
      if (outPath_size > 1)
      {
        outPath = (char *) malloc(outPath_size * sizeof(char));
        memcpy(outPath, optarg, outPath_size);
      }
      arg_index = arg_index + 2;
      pelz_log(LOG_DEBUG, "OutPath option: %.*s", (int) outPath_size, outPath);
      break;
    default:
      return 1;
    }
  }

  //Determine the command arguments
  for (int i = 0; i < 5; i++)
  {
    cmd_arg[i] = check_arg(argv[arg_index + 1 + i]);
    if (cmd_arg[i] == 0)
    {
      break;
    }
  }

  //Check for valid use of OutPath option 
  if (out == true && cmd_arg[0] != SEAL)
  {
    usage(argv[0]);
    free(outPath);
    return 1;
  }

  //Check command arguments
  switch (cmd_arg[0])
  {
    case EMPTY:
      usage(argv[0]);
      return 1;
    case OTHER:
      usage(argv[0]);
      return 1;
    case SEAL:
      if (cmd_arg[1] == OTHER && cmd_arg[2] == EMPTY)
      {
        cmd = CMD_SEAL;
        cmd_param_index = arg_index + 2;
      }
      else
      {
        seal_usage();
        return 1;
      }
      break;
    case EX:
      if (cmd_arg[1] == EMPTY)
      {
        cmd = CMD_EXIT;
      }
      else
      {
        usage(argv[0]);
        return 1;
      }
      break;
    case KEYTABLE:
      if (cmd_arg[1] == REMOVE)
      {
        if (all == true)
        {
          cmd = CMD_REMOVE_ALL_KEYS;
        }
        else if (cmd_arg[2] == OTHER && cmd_arg[3] == EMPTY)
        {
          cmd = CMD_REMOVE_KEY;
          cmd_param_index = arg_index + 3;
        }
        else
        {
          keytable_usage();
          return 1;
        }
      }
      else if (cmd_arg[1] == LIST && cmd_arg[2] == EMPTY)
      {
        cmd = CMD_LIST_KEYS;
      }
      else
      {
        keytable_usage();
        return 1;
      }
      break;
    case PKI:
      if (cmd_arg[1] == LOAD)
      {
        if (cmd_arg[2] == CERT && cmd_arg[3] == OTHER && cmd_arg[4] == EMPTY)
        {
          cmd = CMD_LOAD_CERT;
          cmd_param_index = arg_index + 4;
        }
        else if (cmd_arg[2] == PRIVATE  && cmd_arg[3] == OTHER && cmd_arg[4] == EMPTY)
        {
          cmd = CMD_LOAD_PRIV;
          cmd_param_index = arg_index + 4;
        }
        else
        {
          pki_usage();
          return 1;
        }
      }
      else if (cmd_arg[1] == CERT && cmd_arg[2] == LIST && cmd_arg[3] == EMPTY)
      {
        cmd = CMD_LIST_CERTS;
      }
      else if (cmd_arg[1] == REMOVE)
      {
        if (all == true)
        {
          cmd = CMD_REMOVE_ALL_CERTS;
        }
        else if (cmd_arg[2] == PRIVATE && cmd_arg[3] == EMPTY)
        {
          cmd = CMD_REMOVE_PRIV;
        }
        else if (cmd_arg[2] == OTHER && cmd_arg[3] == EMPTY)
        {
          cmd = CMD_REMOVE_CERT;
          cmd_param_index = arg_index + 3;
        }
        else
        {
          pki_usage();
          return 1;
        }
      }
      else
      {
        pki_usage();
        return 1;
      }
      break;
    case CA:
      if (cmd_arg[1] == LOAD && cmd_arg[2] == OTHER && cmd_arg[3] == EMPTY)
      {
        cmd = CMD_LOAD_CA;
        cmd_param_index = arg_index + 3;
      }
      else if (cmd_arg[1] == LIST && cmd_arg[2] == EMPTY)
      {
        cmd = CMD_LIST_CA;
      }
      else if (cmd_arg[1] == REMOVE)
      {
        if (all == true)
        {
          cmd = CMD_REMOVE_ALL_CA;
        }
        else if (cmd_arg[2] == OTHER && cmd_arg[3] == EMPTY)
        {
          cmd = CMD_REMOVE_CA;
          cmd_param_index = arg_index + 3;
        }
        else
        {
          ca_usage();
          return 1;
        }
      }
      else
      {
        ca_usage();
        return 1;
      }
      break;
    default:
      usage(argv[0]);
      return 1;
  }

  char fifo_name[BUFSIZE];
  size_t fifo_name_len = 0;
  int pid_t = getpid();
  
  //Creating fifo name for pipe creations and use
  sprintf(fifo_name, "%s%d", PELZINTERFACE, pid_t);
  fifo_name_len = strlen(fifo_name);
  pelz_log(LOG_DEBUG, "FIFO Name: %.*s, %d", fifo_name_len, fifo_name, fifo_name_len );
  
  //Creating name pipe (FIFO)
  if (mkfifo(fifo_name, MODE) == 0)
  {
    pelz_log(LOG_DEBUG, "Pipe created successfully");
  }
  else
  {
    pelz_log(LOG_DEBUG, "Error: %s", strerror(errno));
  }

  switch (cmd)
  {
    case CMD_SEAL:
      //Execute the seal command
      pelz_log(LOG_DEBUG, "Seal <path> option");
      if (seal(argv[cmd_param_index], &outPath, outPath_size, tpm))
      {
        pelz_log(LOG_ERR, "Error seal function");
        if(outPath != NULL && outPath_size == 0)
        {
          free(outPath);
        }
        remove_pipe(fifo_name);
        return 1;
      }
      fprintf(stdout, "Successfully sealed contents to file: %s\n", outPath);
      free(outPath);
      break;
    case CMD_EXIT:
      //Execute the exit command
      msg_arg(fifo_name, fifo_name_len, cmd, NULL, 0);
      break;
    case CMD_REMOVE_KEY:
      //Execute the keytable remove <ID> command
      msg_arg(fifo_name, fifo_name_len, cmd, argv[cmd_param_index], (int) strlen(argv[cmd_param_index]));
      break;
    case CMD_REMOVE_ALL_KEYS:
      //Execute the keytable remove all command
      msg_arg(fifo_name, fifo_name_len, cmd, NULL, 0);
      break;
    case CMD_LIST_KEYS:
      //Execute the keytable list command
      msg_list(fifo_name, fifo_name_len, cmd);
      break;
    case CMD_LOAD_CERT:
      //Execute the pki load cert <path> command
      msg_arg(fifo_name, fifo_name_len, cmd, argv[cmd_param_index], (int) strlen(argv[cmd_param_index]));
      break;
    case CMD_LOAD_PRIV:
      //Execute the pki load private <path> command
      msg_arg(fifo_name, fifo_name_len, cmd, argv[cmd_param_index], (int) strlen(argv[cmd_param_index]));
      break;
    case CMD_LIST_CERTS:
      //Execute the pki cert list command
      msg_list(fifo_name, fifo_name_len, cmd);
      break;
    case CMD_REMOVE_CERT:
      //Execute the pki remove <CN> command
      msg_arg(fifo_name, fifo_name_len, cmd, argv[cmd_param_index], (int) strlen(argv[cmd_param_index]));
      break;
    case CMD_REMOVE_ALL_CERTS:
      //Execute the pki remove --all command
      msg_arg(fifo_name, fifo_name_len, cmd, NULL, 0);
      break;
    case CMD_REMOVE_PRIV:
      //Execute the pki remove private command
      msg_arg(fifo_name, fifo_name_len, cmd, NULL, 0);
      break;
    case CMD_LOAD_CA:
      //Execute the ca load <path> command
      msg_arg(fifo_name, fifo_name_len, cmd, argv[cmd_param_index], (int) strlen(argv[cmd_param_index]));
      break;
    case CMD_LIST_CA:
      //Execute the ca list command
      msg_list(fifo_name, fifo_name_len, cmd);
      break;
    case CMD_REMOVE_CA:
      //Execute the ca remove <CN> command
      msg_arg(fifo_name, fifo_name_len, cmd, argv[cmd_param_index], (int) strlen(argv[cmd_param_index]));
      break;
    case CMD_REMOVE_ALL_CA:
      //Execute the ca remove --all command
      msg_arg(fifo_name, fifo_name_len, cmd, NULL, 0);
      break;
    default:
      usage(argv[0]);
      remove_pipe(fifo_name);
      return 1;
  }
  remove_pipe(fifo_name);  
  return 0;
}
