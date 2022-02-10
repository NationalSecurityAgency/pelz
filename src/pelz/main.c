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
#include "sgx_seal_unseal_impl.h"

sgx_enclave_id_t eid = 0;

#define ENCLAVE_PATH "sgx/pelz_enclave.signed.so"

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
    pelz_send_command(msg);
    free(msg);
    if (unlink(PELZSERVICEOUT) == 0)
    {
      pelz_log(LOG_DEBUG, "Second pipe deleted successfully");
    }
    else
    {
      pelz_log(LOG_DEBUG, "Failed to delete the second pipe");
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
        pelz_send_command(msg);
        free(msg);
        free(path_id);
      }
      else
      {
        pki_usage();
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
        pelz_send_command(msg);
        free(msg);
        free(path_id);
      }
      else
      {
        pki_usage();
        free(outPath);
        return 1;
      }
    }
    else
    {
      pki_usage();
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
        pelz_send_command(msg);
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
        pelz_send_command(msg);
        free(msg);
        free(path_id);
      }
      else
      {
        keytable_usage();
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
        pelz_send_command(msg);
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
        pelz_send_command(msg);
        free(msg);
        free(path_id);
      }
      else
      {
        keytable_usage();
        free(outPath);
        return 1;
      }
    }
    else
    {
      keytable_usage();
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

        pelz_log(LOG_DEBUG, "output file not specified, default = %s", outPath);
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
    fprintf(stdout, "Successfully sealed contents to file: %s\n", outPath);
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
