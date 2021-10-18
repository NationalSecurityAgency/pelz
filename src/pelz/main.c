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
#include <kmyth/kmyth.h>
#include <kmyth/file_io.h>

#include "pelz_log.h"
#include "pelz_io.h"

#include "pelz_enclave.h"
#include "kmyth_enclave.h"

sgx_enclave_id_t eid = 0;

#define ENCLAVE_PATH "sgx/pelz_enclave.signed.so"
#define PELZSERVICEIN "/tmp/pelzServiceIn"
#define PELZSERVICEOUT "/tmp/pelzServiceOut"

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
    "                                .nkl or .ski extension. Using -o allows the user to specify their\n"
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

  if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "exit", 4) == 0) && (strlen(argv[arg_index + 1]) == 4))
  {
    msg = (char *) calloc(7, sizeof(char));
    memcpy(msg, "pelz 1", 6);
    pelz_log(LOG_DEBUG, "Message: %s", msg);
    if (write_to_pipe((char *) PELZSERVICEIN, msg))
    {
      pelz_log(LOG_INFO, "Unable to connect to the pelz-service. Please make sure service is running.");
    }
    else
    {
      pelz_log(LOG_INFO, "Pelz command options sent to pelz-service");
    }
    free(msg);
    if (read_from_pipe((char *) PELZSERVICEOUT, &msg))
    {
      pelz_log(LOG_INFO, "Unable to recieve message from the pelz-service.");
    }
    else
    {
      pelz_log(LOG_INFO, "%s", msg);
    }
    free(msg);
    if (unlink(PELZSERVICEOUT) == 0)
    {
      pelz_log(LOG_INFO, "Second pipe deleted successfully");
    }
    else
    {
      pelz_log(LOG_INFO, "Failed to delete the second pipe");
    }
  }
  else if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "load", 4) == 0) && (strlen(argv[arg_index + 1]) == 4))
  {
    pelz_log(LOG_DEBUG, "Load option");
    if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "cert", 4) == 0) && (strlen(argv[arg_index + 2]) == 4))
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
        msg = (char *) calloc((8 + path_id_size), sizeof(char));
        memcpy(msg, "pelz 2 ", 7);
        memcpy(&msg[7], path_id, path_id_size);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        if (write_to_pipe((char *) PELZSERVICEIN, msg))
        {
          pelz_log(LOG_INFO, "Unable to connect to the pelz-service. Please make sure service is running.");
        }
        else
        {
          pelz_log(LOG_INFO, "Pelz command options sent to pelz-service");
        }
        free(msg);
        if (read_from_pipe((char *) PELZSERVICEOUT, &msg))
        {
          pelz_log(LOG_INFO, "Unable to recieve message from the pelz-service.");
        }
        else
        {
          pelz_log(LOG_INFO, "%s", msg);
        }
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
    else if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "private", 7) == 0)
      && (strlen(argv[arg_index + 2]) == 7))
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
        msg = (char *) calloc((8 + path_id_size), sizeof(char));
        memcpy(msg, "pelz 3 ", 7);
        memcpy(&msg[7], path_id, path_id_size);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        if (write_to_pipe((char *) PELZSERVICEIN, msg))
        {
          pelz_log(LOG_INFO, "Unable to connect to the pelz-service. Please make sure service is running.");
        }
        else
        {
          pelz_log(LOG_INFO, "Pelz command options sent to pelz-service");
        }
        free(msg);
        if (read_from_pipe((char *) PELZSERVICEOUT, &msg))
        {
          pelz_log(LOG_INFO, "Unable to recieve message from the pelz-service.");
        }
        else
        {
          pelz_log(LOG_INFO, "%s", msg);
        }
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
  else if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "remove", 6) == 0)
    && (strlen(argv[arg_index + 1]) == 6))
  {
    pelz_log(LOG_DEBUG, "Remove option");
    if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "key", 3) == 0) && (strlen(argv[arg_index + 2]) == 3))
    {
      pelz_log(LOG_DEBUG, "Remove key option");
      if (all && (argv[arg_index + 3] == NULL))
      {
        pelz_log(LOG_DEBUG, "Remove key --all option");
        msg = (char *) calloc(7, sizeof(char));
        memcpy(msg, "pelz 7", 6);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        if (write_to_pipe((char *) PELZSERVICEIN, msg))
        {
          pelz_log(LOG_INFO, "Unable to connect to the pelz-service. Please make sure service is running.");
        }
        else
        {
          pelz_log(LOG_INFO, "Pelz command options sent to pelz-service");
        }
        free(msg);
        if (read_from_pipe((char *) PELZSERVICEOUT, &msg))
        {
          pelz_log(LOG_INFO, "Unable to recieve message from the pelz-service.");
        }
        else
        {
          pelz_log(LOG_INFO, "%s", msg);
        }
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
        msg = (char *) calloc((8 + path_id_size), sizeof(char));
        memcpy(msg, "pelz 6 ", 7);
        memcpy(&msg[7], path_id, path_id_size);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        if (write_to_pipe((char *) PELZSERVICEIN, msg))
        {
          pelz_log(LOG_INFO, "Unable to connect to the pelz-service. Please make sure service is running.");
        }
        else
        {
          pelz_log(LOG_INFO, "Pelz command options sent to pelz-service");
        }
        free(msg);
        if (read_from_pipe((char *) PELZSERVICEOUT, &msg))
        {
          pelz_log(LOG_INFO, "Unable to recieve message from the pelz-service.");
        }
        else
        {
          pelz_log(LOG_INFO, "%s", msg);
        }
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
    else if ((argv[arg_index + 2] != NULL) && (memcmp(argv[arg_index + 2], "cert", 4) == 0)
      && (strlen(argv[arg_index + 2]) == 4))
    {
      pelz_log(LOG_DEBUG, "Remove cert option");
      if (all && (argv[arg_index + 3] == NULL))
      {
        pelz_log(LOG_DEBUG, "Remove cert --all option");
        msg = (char *) calloc(7, sizeof(char));
        memcpy(msg, "pelz 5", 6);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        if (write_to_pipe((char *) PELZSERVICEIN, msg))
        {
          pelz_log(LOG_INFO, "Unable to connect to the pelz-service. Please make sure service is running.");
        }
        else
        {
          pelz_log(LOG_INFO, "Pelz command options sent to pelz-service");
        }
        free(msg);
        if (read_from_pipe((char *) PELZSERVICEOUT, &msg))
        {
          pelz_log(LOG_INFO, "Unable to recieve message from the pelz-service.");
        }
        else
        {
          pelz_log(LOG_INFO, "%s", msg);
        }
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
        msg = (char *) calloc((8 + path_id_size), sizeof(char));
        memcpy(msg, "pelz 4 ", 7);
        memcpy(&msg[7], path_id, path_id_size);
        pelz_log(LOG_DEBUG, "Message: %s", msg);
        if (write_to_pipe((char *) PELZSERVICEIN, msg))
        {
          pelz_log(LOG_INFO, "Unable to connect to the pelz-service. Please make sure service is running.");
        }
        else
        {
          pelz_log(LOG_INFO, "Pelz command options sent to pelz-service");
        }
        free(msg);
        if (read_from_pipe((char *) PELZSERVICEOUT, &msg))
        {
          pelz_log(LOG_INFO, "Unable to recieve message from the pelz-service.");
        }
        else
        {
          pelz_log(LOG_INFO, "%s", msg);
        }
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
  else if ((argv[arg_index + 1] != NULL) && (memcmp(argv[arg_index + 1], "seal", 4) == 0) && (strlen(argv[arg_index + 1]) == 4))
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

      // Verify input path exists with read permissions
      if (verifyInputFilePath(path_id))
      {
        pelz_log(LOG_ERR, "input path (%s) is not valid ... exiting", path_id);
        free(path_id);
        free(outPath);
        return 1;
      }

      uint8_t *data = NULL;
      size_t data_len = 0;

      if (read_bytes_from_file(path_id, &data, &data_len))
      {
        pelz_log(LOG_ERR, "seal input data file read error ... exiting");
        free(data);
        free(path_id);
        free(outPath);
        return 1;
      }
      pelz_log(LOG_DEBUG, "read in %d bytes of data to be wrapped", data_len);

      // validate non-empty plaintext buffer specified
      if (data_len == 0 || data == NULL)
      {
        pelz_log(LOG_ERR, "no input data ... exiting");
        free(data);
        free(path_id);
        free(outPath);
        return 1;
      }

      sgx_create_enclave(ENCLAVE_PATH, 0, NULL, NULL, &eid, NULL);

      uint8_t *sgx_seal = NULL;
      size_t sgx_seal_len = 0;
      uint16_t key_policy = SGX_KEYPOLICY_MRSIGNER;
      sgx_attributes_t attribute_mask;

      attribute_mask.flags = 0;
      attribute_mask.xfrm = 0;

      if (kmyth_sgx_seal_nkl(eid, data, data_len, &sgx_seal, &sgx_seal_len, key_policy, attribute_mask))
      {
        pelz_log(LOG_ERR, "SGX seal failed");
        sgx_destroy_enclave(eid);
        free(data);
        free(path_id);
        free(outPath);
        return 1;
      }

      sgx_destroy_enclave(eid);
      free(data);

      uint8_t *tpm_seal = NULL;
      size_t tpm_seal_len = 0;

      if (tpm)
      {
        char *authString = NULL;
        size_t auth_string_len = 0;
        const char *ownerAuthPasswd = "";
        size_t oa_passwd_len = 0;
        char *cipherString = NULL;
        int *pcrs = NULL;
        int pcrs_len = 0;

        if (tpm2_kmyth_seal(sgx_seal, sgx_seal_len, &tpm_seal, &tpm_seal_len, (uint8_t *) authString, auth_string_len,
            (uint8_t *) ownerAuthPasswd, oa_passwd_len, pcrs, pcrs_len, cipherString))
        {
          pelz_log(LOG_ERR, "Kmyth TPM seal failed");
          free(pcrs);
          free(sgx_seal);
          free(path_id);
          free(outPath);
          free(tpm_seal);
          return 1;
        }
        free(pcrs);
        free(sgx_seal);
      }

      if ((outPath != NULL) && (outPath_size != 0))
      {
        if (tpm)
        {
          if (write_bytes_to_file(outPath, tpm_seal, tpm_seal_len))
          {
            pelz_log(LOG_ERR, "error writing data to .ski file ... exiting");
            free(outPath);
            free(path_id);
            free(tpm_seal);
            return 1;
          }
          free(tpm_seal);
        }
        else
        {
          if (write_bytes_to_file(outPath, sgx_seal, sgx_seal_len))
          {
            pelz_log(LOG_ERR, "error writing data to .nkl file ... exiting");
            free(outPath);
            free(path_id);
            free(sgx_seal);
            return 1;
          }
          free(sgx_seal);
        }
      }
      else
      {
        char *ext;
        const char *TPM_EXT = ".ski";
        const char *NKL_EXT = ".nkl";

        if (tpm)
        {
          ext = (char *) TPM_EXT;
        }
        else
        {
          ext = (char *) NKL_EXT;
        }

        // If output file not specified, set output path to basename(inPath) with
        // a .nkl extension in the directory that the application is being run from.
        char *original_fn = basename(path_id);

        outPath = (char *) malloc((strlen(original_fn) + strlen(ext) + 1) * sizeof(char));

        // Make sure resultant default file name does not have empty basename
        if (outPath == NULL)
        {
          pelz_log(LOG_ERR, "invalid default filename derived ... exiting");
          free(outPath);
          return 1;
        }

        memcpy(outPath, original_fn, strlen(original_fn));
        memcpy(&outPath[strlen(original_fn)], ext, (strlen(ext) + 1));
        free(path_id);

        // Make sure default filename we constructed doesn't already exist
        struct stat st = {
          0
        };
        if (!stat(outPath, &st))
        {
          pelz_log(LOG_ERR, "default output filename (%s) already exists ... exiting", outPath);
          free(outPath);
          return 1;
        }

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
          if (write_bytes_to_file(outPath, sgx_seal, sgx_seal_len))
          {
            pelz_log(LOG_ERR, "error writing data to .nkl file ... exiting");
            free(outPath);
            free(sgx_seal);
            return 1;
          }
          free(sgx_seal);
        }
      }
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
