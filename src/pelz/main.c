/*
 * Contains the main function used to launch the Pelz Key Service
 */

#include <getopt.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "key_table.h"
#include "pelz_service.h"
#include "pelz_log.h"
#include "pelz_io.h"
#include "charbuf.h"

#ifdef PELZ_SGX_UNTRUSTED
#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"
sgx_enclave_id_t eid = 0;

#define ENCLAVE_PATH "sgx/pelz_enclave.signed.so"
#endif

static void usage(const char *prog)
{
  fprintf(stdout,
    "usage: %s [options] \n\n"
    "options are: \n\n"
    " -h or --help                Help (displays this usage).\n"
    " -m or --max_requests        Maximum number of sockets pelz can make available at any given time, default: 100\n"
    " -v or --verbose             Enable detailed logging.\n"
    " -c or --certificate         File path for the Key Server Certificate.\n"
    " -k or --key initialization  File path to text file with Key IDs to be pre loaded into Key Table.\n", prog);
}

const struct option longopts[] = {
  {"help", no_argument, 0, 'h'},
  {"max_requests", required_argument, 0, 'm'},
  {"verbose", no_argument, 0, 'v'},
  {"certificate", required_argument, 0, 'c'},
  {"key initialization", required_argument, 0, 'k'},
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

  int max_requests = 100;
  int options;
  int option_index;
  long mr = 0;
  char *cert = NULL;
  char *key_init = NULL;
  FILE *key_txt_f = 0;
  char buffer[100];             //Buffer size is set to 100 because the file path lengths should be less then that
  charbuf key_id;
  charbuf tmp_key;
  EVP_PKEY *pkey = NULL;

  while ((options = getopt_long(argc, argv, "m:c:k:hv", longopts, &option_index)) != -1)
  {
    switch (options)
    {
    case 'h':
      usage(argv[0]);
      return 0;
    case 'm':
      if (optarg && (mr = atol(optarg)) > 0)
      {
        max_requests = (int) mr;
        break;
      }
      else
      {
        pelz_log(LOG_ERR, "max_request must be an integer. Received invalid option '%s'", optarg);
        return 1;
      }
    case 'v':
      set_applog_severity_threshold(LOG_DEBUG);
      set_applog_output_mode(0);
      break;
    case 'c':
      if (optarg && !file_check(optarg))
      {
        cert = optarg;
        break;
      }
      else
      {
        pelz_log(LOG_ERR, "Key Server Certificate file path invalid");
        return 1;
      }
    case 'k':
      if (optarg && !file_check(optarg))
      {
        key_init = optarg;
        break;
      }
      else
      {
        pelz_log(LOG_ERR, "Key Initialization file path invalid");
        return 1;
      }
    default:
      return 1;
    }
  }

  int ret;

#ifdef PELZ_SGX_UNTRUSTED
  sgx_create_enclave(ENCLAVE_PATH, 0, NULL, NULL, &eid, NULL);
  key_table_init(eid, &ret);
#else
  ret = key_table_init();
#endif

  if (ret)
  {
    pelz_log(LOG_ERR, "Key Table Init Failure");
    return (1);
  }

  if (key_init != NULL)
  {
    key_txt_f = fopen(key_init, "r");
    while (fscanf(key_txt_f, "%s", buffer) == 1)
    {
      if (!file_check(buffer))
      {
        key_id = new_charbuf(strlen(buffer));
        memcpy(key_id.chars, buffer, key_id.len);
        key_table_add(key_id, &tmp_key);
        secure_free_charbuf(&tmp_key);
        free_charbuf(&key_id);
      }
    }
    if (feof(key_txt_f))
    {
      pelz_log(LOG_INFO, "Key initialization file read and keys added to Key Table.");
      fclose(key_txt_f);
    }
    else
    {
      pelz_log(LOG_ERR, "Key initialization file read error.");
      fclose(key_txt_f);
      return (1);
    }
  }

  if (cert != NULL)
  {
    if(cert_extract(cert, &pkey))
    {
      pelz_log(LOG_ERR, "Public Certificate Key failure to extract.");
    }
    else
    {
      pelz_log(LOG_INFO, "Add function to pass key to Key Server.");
    }
  }

  pelz_service((const int) max_requests);

#ifdef PELZ_SGX_UNTRUSTED
  key_table_destroy(eid, &ret);
  sgx_destroy_enclave(eid);
#else
  key_table_destroy();
#endif
  return (0);
}
