/*
 * Contains the main function used to launch the Pelz Key Service
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>

#include "pelz_log.h"
#include "pelz_io.h"

#include "pelz_enclave.h"
sgx_enclave_id_t eid = 0;

static void load_usage()
{
  fprintf(stdout,
    "load <type> <path>              Loads a value of type <type> (currently either cert or private)\n"
    "                                into the pelz-service enclave. These files must be formatted as\n"
    "                                a .ski or .nkl file.\n"
    "load cert <path/to/file>        Loads a server certificate into the pelz-service enclave\n"
    "load private <path/to/file>     Loads a private key for connections to key servers into the\n"
    "                                pelz-service enclave. This will fail if a key is already\n"
    "                                loaded.\n");
}

static void remove_usage()
{
  fprintf(stdout,
    "remove <target> <id> [options]  Removes a value of type <target> (currently either cert or key)\n"
    "                                from memory within the pelz-service enclave. The -a option may\n"
    "                                be used to drop all server certificates or all keys.\n"
    "remove key <id> [options]       Removes a key with a specified id from the pelz-service enclave if it\n"
    "                                exists. If -a is given, no id is required.\n"
    "remove cert <path> [options]    Removes the server cert at the specified path from the pelz-service\n"
    "                                loaded certificates. If -a is given, no path is required.\n"
    "-a or --all                     Used only with remove to indicate removing all server certificates or\n"
    "                                keys from the pelz-service key table.\n");
}

static void seal_usage()
{
  fprintf(stdout,
    "seal <path> [options]           Seals the input file to the pelz-service enclave. This creates a .nkl\n"
    "                                file. This can also be used in conjunction with the TPM to double\n"
    "                                seal a file and create a .ski file as output.\n"
    "-t or --tpm                     Use the TPM as well when sealing. This requires the TPM to be enabled.\n"
    "-o or --output <output path>    By default, seal will output a new file with the same name but the\n"
    "                                .nkl extension. Using -o allows the user to specify their output\n"
    "                                file destination.\n");
}

static void usage(const char *prog)
{
  fprintf(stdout,
    "usage: %s <keywords> [options] \n\n"
    "keywords are: \n\n"
    "-d or --debug                   Enable debug messaging and logging.\n"
    "-h or --help                    Help (displays this usage).\n\n"
    "exit                            Terminate running pelz-service\n\n", prog);
  load_usage();
  fprintf(stdout, "\n");
  remove_usage();
  fprintf(stdout, "\n");
  seal_usage();
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
  set_applog_severity_threshold(LOG_WARNING);

  int options;
  int option_index;
  int arg_index = 0;
  bool all = false;
  bool tpm = false;
  char *output = NULL;
  size_t output_size = 0;
  char *path_id = NULL;
  size_t path_id_size = 0;
  char *msg;

  if (argc == 1)
  {
    usage(argv[0]);
    return 0;
  }

  while ((options = getopt_long(argc, argv, "hdato:", longopts, &option_index)) != -1)
  {
    switch (options)
    {
    case 'h':
      usage(argv[0]);
      return 0;
    case 'd':
      set_applog_severity_threshold(LOG_DEBUG);
      set_applog_output_mode(0);
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
      output_size = strlen(optarg) + 1;
      if (output_size > 1)
      {
        output = (char *) malloc(output_size * sizeof(char));
        memcpy(output, optarg, output_size);
      }
      arg_index = arg_index + 2;
      pelz_log(LOG_DEBUG, "Output option: %.*s", (int) output_size, output);
      break;
    default:
      return 1;
    }
  }

  if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "exit", 4) == 0))
  {
    msg = (char *) calloc(8, sizeof(char));
    memcpy(msg, "pelz -e", 7);
    pelz_log(LOG_DEBUG, "Message: %s", msg);
    write_to_pipe(msg);
    free(msg);
  }
  else if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "load", 4) == 0))
  {
    pelz_log(LOG_DEBUG, "Load option");
    if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "cert", 4) == 0))
    {
      pelz_log(LOG_DEBUG, "Load cert option");
      if (argv[arg_index + 3] != NULL)
      {
        pelz_log(LOG_DEBUG, "Load cert <path> option");
        path_id_size = strlen(argv[arg_index + 3]) + 1;
        if (path_id_size > 1)
        {
          path_id = (char *) malloc(path_id_size * sizeof(char));
          memcpy(path_id, argv[arg_index + 3], path_id_size);
        }
        pelz_log(LOG_DEBUG, "<path> set: %.*s", (int) path_id_size, path_id);
        if (file_check(path_id))
        {
          printf("File %s is invalid.\n", path_id);
          free(path_id);
          free(output);
          return 1;
        }
        msg = (char *) calloc((12 + path_id_size), sizeof(char));
        memcpy(msg, "pelz -l -c ", 11);
        memcpy(&msg[11], path_id, path_id_size);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe(msg);
        free(msg);
        free(path_id);
      }
      else
      {
        load_usage();
        free(output);
        return 1;
      }
    }
    else if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "private", 3) == 0))
    {
      pelz_log(LOG_DEBUG, "Load private option");
      if (argv[arg_index + 3] != NULL)
      {
        pelz_log(LOG_DEBUG, "Load private <path> option");
        path_id_size = strlen(argv[arg_index + 3]) + 1;
        if (path_id_size > 1)
        {
          path_id = (char *) malloc(path_id_size * sizeof(char));
          memcpy(path_id, argv[arg_index + 3], path_id_size);
        }
        pelz_log(LOG_DEBUG, "<path> set: %.*s", (int) path_id_size, path_id);
        if (file_check(path_id))
        {
          printf("File %s is invalid.\n", path_id);
          free(path_id);
          free(output);
          return 1;
        }
        msg = (char *) calloc((12 + path_id_size), sizeof(char));
        memcpy(msg, "pelz -l -p ", 11);
        memcpy(&msg[11], path_id, path_id_size);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe(msg);
        free(msg);
        free(path_id);
      }
      else
      {
        load_usage();
        free(output);
        return 1;
      }
    }
    else
    {
      load_usage();
      free(output);
      return 1;
    }
  }
  else if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "remove", 6) == 0))
  {
    pelz_log(LOG_DEBUG, "Remove option");
    if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "key", 3) == 0))
    {
      pelz_log(LOG_DEBUG, "Remove key option");
      if (all && (argv[arg_index + 3] == NULL))
      {
        pelz_log(LOG_DEBUG, "Remove key --all option");
        msg = (char *) calloc(14, sizeof(char));
        memcpy(msg, "pelz -r -k -a", 13);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe(msg);
        free(msg);
      }
      else if ((argv[arg_index + 3] != NULL) && !all)
      {
        pelz_log(LOG_DEBUG, "Remove key <id> option");
        path_id_size = strlen(argv[arg_index + 3]) + 1;
        if (path_id_size > 1)
        {
          path_id = (char *) malloc(path_id_size * sizeof(char));
          memcpy(path_id, argv[arg_index + 3], path_id_size);
        }
        pelz_log(LOG_DEBUG, "<id> set: %.*s", (int) path_id_size, path_id);
        msg = (char *) calloc((12 + path_id_size), sizeof(char));
        memcpy(msg, "pelz -r -k ", 11);
        memcpy(&msg[11], path_id, path_id_size);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe(msg);
        free(msg);
        free(path_id);
      }
      else
      {
        remove_usage();
        free(output);
        return 1;
      }
    }
    else if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "cert", 4) == 0))
    {
      pelz_log(LOG_DEBUG, "Remove cert option");
      if (all && (argv[arg_index + 3] == NULL))
      {
        pelz_log(LOG_DEBUG, "Remove cert --all option");
        msg = (char *) calloc(14, sizeof(char));
        memcpy(msg, "pelz -r -c -a", 13);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe(msg);
        free(msg);
      }
      else if (argv[arg_index + 3] != NULL && !all)
      {
        pelz_log(LOG_DEBUG, "Remove cert <path> option");
        path_id_size = strlen(argv[arg_index + 3]) + 1;
        if (path_id_size > 1)
        {
          path_id = (char *) malloc(path_id_size * sizeof(char));
          memcpy(path_id, argv[arg_index + 3], path_id_size);
        }
        pelz_log(LOG_DEBUG, "<path> set: %.*s", (int) path_id_size, path_id);
        if (file_check(path_id))
        {
          printf("File %s is invalid.\n", path_id);
          free(path_id);
          free(output);
          return 1;
        }
        msg = (char *) calloc((12 + path_id_size), sizeof(char));
        memcpy(msg, "pelz -r -c ", 11);
        memcpy(&msg[11], path_id, path_id_size);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        write_to_pipe(msg);
        free(msg);
        free(path_id);
      }
      else
      {
        remove_usage();
        free(output);
        return 1;
      }
    }
    else
    {
      remove_usage();
      free(output);
      return 1;
    }
  }
  else if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "seal", 4) == 0))
  {
    pelz_log(LOG_DEBUG, "Seal option");
    if (argv[arg_index + 2] != NULL)
    {
      pelz_log(LOG_DEBUG, "Seal <path> option");
      path_id_size = strlen(argv[arg_index + 2]) + 1;
      if (path_id_size > 1)
      {
        path_id = (char *) malloc(path_id_size * sizeof(char));
        memcpy(path_id, argv[arg_index + 2], path_id_size);
      }
      pelz_log(LOG_DEBUG, "<path> set: %.*s", (int) path_id_size, path_id);
      if (file_check(path_id))
      {
        printf("File %s is invalid.\n", path_id);
        free(path_id);
        free(output);
        return 1;
      }
      free(path_id);
      if ((output != NULL) && (output_size != 0))
      {
        printf("SGX seal to output call not added\n");
      }
      else
      {
        printf("SGX seal call not added\n");
      }
      if (tpm)
      {
        printf("Kmyth TPM call not added\n");
      }
    }
    else
    {
      seal_usage();
      free(output);
      return 1;
    }
  }
  else
  {
    usage(argv[0]);
    free(output);
    return 1;
  }

  free(output);
  return 0;
}
