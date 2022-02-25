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
}

const struct option longopts[] = {
  {"help", no_argument, 0, 'h'},
  {"debug", no_argument, 0, 'd'},
  {"tpm", no_argument, 0, 't'},
  {"output", required_argument, 0, 'o'},
  {"all", no_argument, 0, 'a'},
  {0, 0, 0, 0}
};

//Main function for the Pelz Service application
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
  bool all = false;
  bool tpm = false;
  bool out = false;
  char *outPath = NULL;
  size_t outPath_size = 0;
  char *msg = NULL;

  if (argc == 1)
  {
    usage(argv[0]);
    return 0;
  }

  //While function to options from command line
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

  //Start of command line option checks and execution
  //Checking for exit command then execution
  if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "exit", 4) == 0) && (strlen(argv[arg_index + 1]) == 4))
  {
    //Create message to be sent to service through pipe
    msg = (char *) calloc((8 + fifo_name_len), sizeof(char));
    memcpy(msg, "pelz 1 ", 7);
    memcpy(&msg[7], fifo_name, fifo_name_len);
    pelz_log(LOG_DEBUG, "Message: %s", msg);
    write_to_pipe((char*) PELZSERVICE, msg);
    free(msg);
    if (read_listener(fifo_name))
    {
      pelz_log(LOG_DEBUG, "Error read from pipe.");
    }
  }

  //Checking for keytable command
  else if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "keytable", 8) == 0) && (strlen(argv[arg_index + 1]) == 8))
  {
    pelz_log(LOG_DEBUG, "keytable options");

    //Checking for keytable remove command
    if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "remove", 6) == 0) && (strlen(argv[arg_index + 2]) == 6))
    {
      pelz_log(LOG_DEBUG, "keytable remove options");

      //Checking for keytable remove all command
      if (all)
      {
        pelz_log(LOG_DEBUG, "keytable remove --all option");

        //Create message to be sent to service through pipe
        msg = (char *) calloc((8 + fifo_name_len), sizeof(char));
        memcpy(msg, "pelz 3 ", 7);
        memcpy(&msg[7], fifo_name, fifo_name_len);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe((char*) PELZSERVICE, msg);
        free(msg);
        if (read_listener(fifo_name))
        {
          pelz_log(LOG_DEBUG, "Error read from pipe.");
        }
      }

      //Checking for keytable remove <id> command
      else if (argv[arg_index + 3] != NULL)
      {
        pelz_log(LOG_DEBUG, "keytable remove <id> option");

        //Create message to be sent to service through pipe
        msg = (char *) calloc((9 + fifo_name_len + strlen(argv[arg_index + 3])), sizeof(char));
        memcpy(msg, "pelz 2 ", 7);
        memcpy(&msg[7], fifo_name, fifo_name_len);
        memcpy(&msg[(7 + fifo_name_len)], " ", 1);
        memcpy(&msg[(8 + fifo_name_len)], argv[arg_index + 3], (strlen(argv[arg_index + 3]) + 1));
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe((char*) PELZSERVICE, msg);
        free(msg);
        if (read_listener(fifo_name))
        {
          pelz_log(LOG_DEBUG, "Error read from pipe.");
        }
      }

      //If keytable command is invalid then print keytable usage for user
      else
      {
        keytable_usage();
        remove_pipe(fifo_name);
        return 1;
      }
    }

    //Checking for keytable list command
    else if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "list", 4) == 0)
      && (strlen(argv[arg_index + 2]) == 4))
    {
      pelz_log(LOG_DEBUG, "keytable list option");
      if (argv[arg_index + 3] == NULL)
      {
        //Create message to be sent to service through pipe
        msg = (char *) calloc((8 + fifo_name_len), sizeof(char));
        memcpy(msg, "pelz 4 ", 7);
        memcpy(&msg[7], fifo_name, fifo_name_len);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe((char*) PELZSERVICE, msg);
        free(msg);
        do
        {
          if (read_listener(fifo_name))
          {
            break;
          }
        } while (1);
      }

      //If keytable command is invalid then print keytable usage for user
      else
      {
        keytable_usage();
        remove_pipe(fifo_name);
        return 1;
      }
    }

    //If keytable command is invalid then print keytable usage for user
    else
    {
      keytable_usage();
      remove_pipe(fifo_name);
      return 1;
    }
  }

  //Checking for pki command
  else if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "pki", 3) == 0)
    && (strlen(argv[arg_index + 1]) == 3))
  {
    pelz_log(LOG_DEBUG, "pki options");

    //Checking for pki load command
    if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "load", 4) == 0) && (strlen(argv[arg_index + 2]) == 4))
    {
      pelz_log(LOG_DEBUG, "pki load options");

      //Checking for pki load cert command
      if ((argv[arg_index + 3] != NULL) && (memcmp(argv[arg_index + 3], "cert", 4) == 0) && (strlen(argv[arg_index + 3]) == 4))
      {
        pelz_log(LOG_DEBUG, "pki load cert option");

        //Checking for pki load cert <path> command
        if (argv[arg_index + 4] != NULL)
        {      
          //Checking if <path> points to an existing file 
          if (file_check(argv[arg_index + 4]))
          {
            pelz_log(LOG_DEBUG, "File %s is invalid.", argv[arg_index + 4]);
            remove_pipe(fifo_name);
            return 1;
          }

          //Create message to be sent to service through pipe
          msg = (char *) calloc((9 + fifo_name_len + strlen(argv[arg_index + 4])), sizeof(char));
          memcpy(msg, "pelz 5 ", 7);
          memcpy(&msg[7], fifo_name, fifo_name_len);
          memcpy(&msg[(7 + fifo_name_len)], " ", 1);
          memcpy(&msg[(8 + fifo_name_len)], argv[arg_index + 4], (strlen(argv[arg_index + 4]) + 1));
          pelz_log(LOG_DEBUG, "Message: %s", msg);
          write_to_pipe((char*) PELZSERVICE, msg);
          free(msg);
          if (read_listener(fifo_name))
          {
            pelz_log(LOG_DEBUG, "Error read from pipe.");
          }
        }

        //If pki command is invalid then print pki usage for user
        else
        {
          pki_usage();
          remove_pipe(fifo_name);
          return 1;
        }
      }

      //Checking for pki load private command
      else if ((argv[arg_index + 3] != NULL) && (memcmp(argv[arg_index + 3], "private", 7) == 0) 
                && (strlen(argv[arg_index + 3]) == 7))
      {
        pelz_log(LOG_DEBUG, "pki load private option");

        //Checking for pki load private <path> command
        if (argv[arg_index + 4] != NULL)
        {
          //Checking if <path> points to an existing file 
          if (file_check(argv[arg_index + 4]))
          {
            pelz_log(LOG_DEBUG, "File %s is invalid.", argv[arg_index + 4]);
            remove_pipe(fifo_name);
            return 1;
          }

          //Create message to be sent to service through pipe
          msg = (char *) calloc((9 + fifo_name_len + strlen(argv[arg_index + 4])), sizeof(char));
          memcpy(msg, "pelz 6 ", 7);
          memcpy(&msg[7], fifo_name, fifo_name_len);
          memcpy(&msg[(7 + fifo_name_len)], " ", 1);
          memcpy(&msg[(8 + fifo_name_len)], argv[arg_index + 4], (strlen(argv[arg_index + 4]) + 1));
          pelz_log(LOG_DEBUG, "Message: %s", msg);
          write_to_pipe((char*) PELZSERVICE, msg);
          free(msg);
          if (read_listener(fifo_name))
          {
            pelz_log(LOG_DEBUG, "Error read from pipe.");
          }
        }

        //If pki command is invalid then print pki usage for user
        else
        {
          pki_usage();
          remove_pipe(fifo_name);
          return 1;
        }
      }

      //If pki command is invalid then print pki usage for user
      else
      {
        pki_usage();
        remove_pipe(fifo_name);
        return 1;
      }
    }

    //Checking for pki cert command
    else if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "cert", 4) == 0)
      && (strlen(argv[arg_index + 2]) == 4))
    {
      pelz_log(LOG_DEBUG, "pki cert option");

      //Checking for pki cert list command
      if (argv[arg_index + 3] != NULL && (memcmp(argv[arg_index + 3], "list", 4) == 0)
      && (strlen(argv[arg_index + 3]) == 4))
      {
        pelz_log(LOG_DEBUG, "pki cert list option");
        if (argv[arg_index + 4] == NULL)
        {
          //Create message to be sent to service through pipe
          msg = (char *) calloc((8 + fifo_name_len), sizeof(char));
          memcpy(msg, "pelz 7 ", 7);
          memcpy(&msg[7], fifo_name, fifo_name_len);
          pelz_log(LOG_DEBUG, "Message: %s", msg);
          write_to_pipe((char*) PELZSERVICE, msg);
          free(msg);
          do
          {
            if(read_listener(fifo_name))
            {
              break;
            }
          } while (1);
        }

        //If pki command is invalid then print pki usage for user
        else
        {
          pki_usage();
          remove_pipe(fifo_name);
          return 1;
        }
      }

      //If pki command is invalid then print pki usage for user
      else
      {
        pki_usage();
        remove_pipe(fifo_name);
        return 1;
      }
    }

    //Checking for pki remove command
    else if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "remove", 6) == 0)
    && (strlen(argv[arg_index + 2]) == 6))
    {
      pelz_log(LOG_DEBUG, "pki remove options");

      //Checking for pki remove all command
      if (all)
      {
        pelz_log(LOG_DEBUG, "pki remove --all option");

        //Create message to be sent to service through pipe
        msg = (char *) calloc((8 + fifo_name_len), sizeof(char));
        memcpy(msg, "pelz 9 ", 7);
        memcpy(&msg[7], fifo_name, fifo_name_len);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe((char*) PELZSERVICE, msg);
        free(msg);
        if (read_listener(fifo_name))
        {
          pelz_log(LOG_DEBUG, "Error read from pipe.");
        }
      }

      //Checking for pki remove <private> command
      else if ((argv[arg_index + 3] != NULL) && (memcmp(argv[arg_index + 3], "private", 7) == 0)
      && (strlen(argv[arg_index + 3]) == 7))
      {
        pelz_log(LOG_DEBUG, "pki remove <private> option");

        //Create message to be sent to service through pipe
        msg = (char *) calloc((9 + fifo_name_len), sizeof(char));
        memcpy(msg, "pelz 10 ", 8);
        memcpy(&msg[8], fifo_name, fifo_name_len);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe((char*) PELZSERVICE, msg);
        free(msg);
        if (read_listener(fifo_name))
        {
          pelz_log(LOG_DEBUG, "Error read from pipe.");
        }
      }

      //Checking for pki remove <CN> command
      else if (argv[arg_index + 3] != NULL)
      {
        pelz_log(LOG_DEBUG, "pki remove <CN> option");

        //Create message to be sent to service through pipe
        msg = (char *) calloc((9 + fifo_name_len + strlen(argv[arg_index + 3])), sizeof(char));
        memcpy(msg, "pelz 8 ", 7);
        memcpy(&msg[7], fifo_name, fifo_name_len);
        memcpy(&msg[(7 + fifo_name_len)], " ", 1);
        memcpy(&msg[(8 + fifo_name_len)], argv[arg_index + 3], (strlen(argv[arg_index + 3]) + 1));
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe((char*) PELZSERVICE, msg);
        free(msg);
        if (read_listener(fifo_name))
        {
          pelz_log(LOG_DEBUG, "Error read from pipe.");
        }
      }

      //If pki command is invalid then print pki usage for user
      else
      {
        pki_usage();
        remove_pipe(fifo_name);
        return 1;
      }
    }

    //If pki command is invalid then print pki usage for user
    else
    {
      pki_usage();
      remove_pipe(fifo_name);
      return 1;
    }
  }

  //Checking for seal command
  else if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "seal", 4) == 0) && (strlen(argv[arg_index + 1]) == 4))
  {
    pelz_log(LOG_DEBUG, "Seal option");
    if (argv[arg_index + 2] != NULL)
    {
      pelz_log(LOG_DEBUG, "Seal <path> option");

      if (seal(argv[arg_index + 2], &outPath, outPath_size, tpm))
      {
        pelz_log(LOG_ERR, "Error seal function");
        if(outPath != NULL && outPath_size == 0)
        {
          free(outPath);
        }
        return 1;
      }
      fprintf(stdout, "Successfully sealed contents to file: %s\n", outPath);
      free(outPath);
    }
    else
    {
      seal_usage();
      remove_pipe(fifo_name);
      return 1;
    }
  }
  //If command invalid then print usage for user
  else
  {
    usage(argv[0]);
    remove_pipe(fifo_name);
    return 1;
  }
  remove_pipe(fifo_name);  
  return 0;
}
