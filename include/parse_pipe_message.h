#ifndef INCLUDE_PARSE_PIPE_MESSAGE_H_
#define INCLUDE_PARSE_PIPE_MESSAGE_H_

#include "charbuf.h"
#include "pelz_request_handler.h"

typedef enum
{ INVALID,             //Invalid pipe command received by pelz-service.
  EXIT,                //Successfully initiated termination of pelz-service.
  UNABLE_RD_F,         //Unable to read file
  TPM_UNSEAL_FAIL,     //TPM unseal faile
  SGX_UNSEAL_FAIL,     //SGX unseal failed
  ADD_CERT_FAIL,       //Failure to add cert
  LOAD_CERT,           //Successfully loaded certificate file into pelz-service.
  INVALID_EXT_CERT,    //Invalid certificate file, unable to load.
  ADD_PRIV_FAIL,       //Failure to add private
  LOAD_PRIV,           //Successfully loaded private key into pelz-service.
  INVALID_EXT_PRIV,    //Invalid private key file, unable to load.
  RM_CERT_FAIL,        //Failure to remove cert
  RM_CERT,             //Removed cert
  CERT_TAB_DEST_FAIL,  //Server Table Destroy Failure
  RM_ALL_CERT,         //All certs removed
  RM_KEK_FAIL,         //Failure to remove key
  RM_KEK,              //Removed key
  KEK_TAB_DEST_FAIL,   //Key Table Destroy Failure
  RM_KEK_ALL,          //All keys removed
  ERR_CHARBUF,         //Charbuf creation error.
  X509_FAIL,           //Unable to load file. Files must originally be in the DER format prior to sealing.
  RM_PRIV_FAIL,        //Failure to remove private pkey
  RM_PRIV,             //Removed private pkey
  NO_KEY_LIST,         //No entries in Key Table.
  KEY_LIST,            //Key Table List: list
  NO_SERVER_LIST,      //No entries in Server Table.
  SERVER_LIST,         //PKI Certificate List: list
  LOAD_CA_FAIL,        //Failure to load CA cert
  LOAD_CA,             //Loaded CA cert
  RM_CA_FAIL,          //Failure to remove CA cert
  RM_CA,               //Removed CA cert
  RM_CA_ALL_FAIL,      //Removed all CA certs
  RM_CA_ALL,           //Removed all CA certs
  NO_CA_LIST,          //No entries in CA Table.
  CA_LIST,             //CA Certificate List: list
} ParseResponseStatus;

#ifdef __cplusplus
extern "C"
{
#endif
/**
 * <pre>
 * Takes a message from the Pelz FIFO pipe then parses and executes the command
 * from message
 * </pre>
 *
 * @param[in] tokens Tokenized message from the pipe to be parsed and executed
 * @param[in] num_tokens The number of tokens output
 * @param[out] response Response to be sent to the second pipe 
 *
 * @return ParseResponseStatus status message indicating the outcome of parse
 */
  ParseResponseStatus parse_pipe_message(char **tokens, size_t num_tokens);

#ifdef __cplusplus
}
#endif

#endif
