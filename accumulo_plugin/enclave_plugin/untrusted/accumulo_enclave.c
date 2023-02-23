/*
 * Contains the main function used to launch the Pelz Accumulo Plug-in
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
#include "charbuf.h"
#include "file_enc_dec.h"
#include "interface.h"

#include "accumulo_enclave.h"

sgx_enclave_id_t eid = 0;

#define BUFSIZE 1024
#define MODE 0600

static void seal_usage(void)
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
}

const struct option longopts[] = {
  {"help", no_argument, 0, 'h'},
  {"debug", no_argument, 0, 'd'},
  {"output", required_argument, 0, 'o'},
  {0, 0, 0, 0}
};

//Main function for the pelz command interface application
int main(int argc, char **argv)
{
  set_app_name("accumulo_plug_in");
  set_app_version("0.0.0");
  set_applog_max_msg_len(1024);
  set_applog_path("/var/log/accumulo_plug_in.log");
  set_applog_severity_threshold(LOG_INFO);
  set_applog_output_mode(0);

  int options;
  int option_index;
  int arg_index = 0;
  int cmd = -1;
  int cmd_param_index = 0;  // index in argv of the first non-keyword command parameter
  CmdArgValue cmd_arg[6] = { EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY };
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
  for (int i = 0; i < 6; i++)
  {
    cmd_arg[i] = check_arg(argv[arg_index + 1 + i]);
    if (cmd_arg[i] == 0)
    {
      break;
    }
  }

  //Check for valid use of OutPath option 
  if (out == true && cmd_arg[0] != ENC && cmd_arg[0] != DEC )
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
    case ENC:
      if (cmd_arg[1] == OTHER && cmd_arg[2] == EMPTY)
      {
        cmd = CMD_ENCRYPT;
        cmd_param_index = arg_index + 2;
      }
      break;
    case DEC:
      if (cmd_arg[1] == OTHER && cmd_arg[2] == EMPTY)
      {
        cmd = CMD_DECRYPT;
        cmd_param_index = arg_index + 2;
      }
      break;
    default:
      usage(argv[0]);
      return 1;
  }

  switch (cmd)
  {
    case CMD_ENCRYPT:
      //Execute the file encrypt command
      pelz_log(LOG_DEBUG, "Encrypt file <path> option");
      if (file_encrypt(argv[cmd_param_index], &outPath, outPath_size))
      {
        pelz_log(LOG_ERR, "Error encrypt function");
        if(outPath != NULL)
        {
          free(outPath);
        }
        return 1;
      }
      fprintf(stdout, "Successfully encrypted file contents to file: %s\n", outPath);
      free(outPath);
      break;
    case CMD_DECRYPT:
      //Execute the file decrypt command
      pelz_log(LOG_DEBUG, "Decrypt file <path> option");
      if (file_decrypt(argv[cmd_param_index], &outPath, outPath_size))
      {
        pelz_log(LOG_ERR, "Error encrypt function");
        if(outPath != NULL)
        {
          free(outPath);
        }
        return 1;
      }
      fprintf(stdout, "Successfully decrypted file contents to file: %s\n", outPath);
      free(outPath);
      break;
    default:
      usage(argv[0]);
      return 1;
  }
  return 0;
}
