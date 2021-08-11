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
#include <kmyth/kmyth.h>

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
    "                                .nklor .ski extension. Using -o allows the user to specify their\n"
    "                                output file destination.\n");
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
  set_applog_severity_threshold(LOG_INFO);
  set_applog_output_mode(0);

  int options;
  int option_index;
  int arg_index = 0;
  bool all = false;
  bool tpm = false;
  char *outPath = NULL;
  size_t outPath_size = 0;
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
          pelz_log(LOG_INFO, "File %s is invalid.", path_id);
          free(path_id);
          free(outPath);
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
        free(outPath);
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
          pelz_log(LOG_INFO, "File %s is invalid.", path_id);
          free(path_id);
          free(outPath);
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
        free(outPath);
        return 1;
      }
    }
    else
    {
      load_usage();
      free(outPath);
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
        free(outPath);
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
          pelz_log(LOG_INFO, "File %s is invalid.", path_id);
          free(path_id);
          free(outPath);
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
        free(outPath);
        return 1;
      }
    }
    else
    {
      remove_usage();
      free(outPath);
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
        pelz_log(LOG_INFO, "File %s is invalid.", path_id);
        free(path_id);
        free(outPath);
        return 1;
      }

      /*
       * uint8_t* sgx_seal = NULL;
       * size_t sgx_seal_len = 0;
       *
       * if (sgx_seal_file(path_id, &sgx_seal, &sgx_seal_len)
       * {
       *   pelz_log(LOG_ERROR, "SGX seal failed");
       *   free(path_id);
       *   free(outPath);
       *   return 1;
       * }
       */

      uint8_t *tpm_seal = NULL;
      size_t tpm_seal_len = 0;

      if (tpm)
      {
        //pelz_log(LOG_INFO, "Kmyth TPM call not added");
        char *authString = NULL;
        size_t auth_string_len = 0;
        const char *ownerAuthPasswd = "";
        size_t oa_passwd_len = 0;
        char *pcrsString = NULL;
        char *cipherString = NULL;
        int *pcrs = NULL;
        int pcrs_len = 0;

        //if (tpm2_kmyth_seal(sgx_seal, sgx_seal_len, &tpm_seal, &tpm_seal_len,
        if (tpm2_kmyth_seal_file(path_id, &tpm_seal, &tpm_seal_len, (uint8_t *) authString, auth_string_len,
            (uint8_t *) ownerAuthPasswd, oa_passwd_len, pcrs, pcrs_len, cipherString))
        {
          pelz_log(LOG_ERR, "Kmyth TPM seal failed");
          free(pcrs);
          free(path_id);
          free(outPath);
          free(tpm_seal);
          return 1;
        }
        free(pcrs);
      }

      if ((outPath != NULL) && (outPath_size != 0))
      {
        pelz_log(LOG_INFO, "SGX seal to outPath call not added");

        if (tpm)
        {
          if (write_bytes_to_file(outPath, tpm_seal, tpm_seal_len))
          {
            pelz_log(LOG_ERR, "error writing data to .ski file ... exiting");
            free(outPath);
            free(tpm_seal);
            return 1;
          }
          free(tpm_seal);
        }
        else
        {
          /*
             if (write_bytes_to_file(outPath, sgx_seal, sgx_seal_len))
             {
             pelz_log(LOG_ERR, "error writing data to .nkl file ... exiting");
             free(outPath);
             free(sgx_seal);
             return 1;
             }
             free(sgx_seal);
           */
          pelz_log(LOG_INFO, "SGX seal call not added");
        }
      }
      else
      {
        char ext[4];            // 4 is the length of a file extension with the period

        if (tpm)
          memcpy(ext, ".ski", 4);
        else
          memcpy(ext, ".nkl", 4);

        // If output file not specified, set output path to basename(inPath) with
        // a .nkl extension in the directory that the application is being run from.
        char *original_fn = basename(path_id);
        char *temp_str = (char *) malloc((strlen(original_fn) + 5) * sizeof(char));

        strncpy(temp_str, original_fn, strlen(original_fn));

        // Remove any leading '.'s
        while (*temp_str == '.')
        {
          memmove(temp_str, temp_str + 1, strlen(temp_str) - 1);
        }
        char *scratch;

        // Everything beyond first '.' in original filename, with any leading
        // '.'(s) removed, is treated as extension
        temp_str = strtok_r(temp_str, ".", &scratch);

        // Append file extension
        strncat(temp_str, ext, 5);

        outPath_size = strlen(temp_str) + 1;
        // Make sure resultant default file name does not have empty basename
        if (outPath_size < 6)
        {
          pelz_log(LOG_ERR, "invalid default filename derived ... exiting");
          free(temp_str);
          return 1;
        }
        // Make sure default filename we constructed doesn't already exist
        struct stat st = { 0 };
        if (!stat(temp_str, &st))
        {
          pelz_log(LOG_ERR, "default output filename (%s) already exists ... exiting", temp_str);
          free(temp_str);
          return 1;
        }
        // Go ahead and make the default value the output path
        outPath = (char *) malloc(outPath_size * sizeof(char));
        memcpy(outPath, temp_str, outPath_size);
        free(temp_str);
        pelz_log(LOG_WARNING, "output file not specified, default = %s", outPath);

        if (tpm)
        {
          if (write_bytes_to_file(outPath, tpm_seal, tpm_seal_len))
          {
            pelz_log(LOG_ERR, "error writing data to .ski file ... exiting");
            free(outPath);
            free(tpm_seal);
            return 1;
          }
          free(tpm_seal);
        }
        else
        {
          /*
             if (write_bytes_to_file(outPath, sgx_seal, sgx_seal_len))
             {
             pelz_log(LOG_ERR, "error writing data to .nkl file ... exiting");
             free(outPath);
             free(sgx_seal);
             return 1;
             }
             free(sgx_seal);
           */
          pelz_log(LOG_INFO, "SGX seal call not added");
        }
      }
      free(path_id);
    }
    else
    {
      seal_usage();
      free(outPath);
      return 1;
    }
  }
  else
  {
    usage(argv[0]);
    free(outPath);
    return 1;
  }

  free(outPath);
  return 0;
}
