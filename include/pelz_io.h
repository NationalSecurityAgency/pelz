#ifndef INCLUDE_PELZ_IO_H_
#define INCLUDE_PELZ_IO_H_

#include "charbuf.h"
#include "pelz_request_handler.h"

#define PELZSERVICE "/tmp/pelzService"
#define PELZINTERFACE "/tmp/pelzInterface"

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

typedef enum
{ NO_EXT, NKL, SKI } ExtensionType;

#ifdef __cplusplus
extern "C"
{
#endif
/**
 * <pre>
 * This function returns an ExtensionType to tell program if filename has a .nkl or .ski extension
 * </pre>
 *
 * @param[in] filename Contains the file name string
 *
 * @return ExtensionType
 */
  ExtensionType get_file_ext(char *filename);

/**
 * <pre>
 * Load key from location stated by Key ID
 * <pre>
 *
 * @param[in] key_id.len     the length of the key identifier
 * @param[in] key_id.chars   the key identifier
 *
 * @return 0 on success, 1 on error
 */
  int key_load(charbuf key_id);

/**
 * <pre>
 * Using key_id to check if there is actual file
 * <pre>
 *
 * @param[in] key_id The Identifier for the Key which is also file path and name
 *
 * @return 0 on success, 1 on error
 */
  int file_check(char *file_path);

/**
 * <pre>
 * Writes a message to an already-opened FIFO pipe
 * </pre>
 *
 * @param[in] fd The FIFO pipe file descriptor
 * @param[in] msg Message to be sent along the pipe, null-terminated
 *
 * @return 0 if success, 1 if error
 */
  int write_to_pipe_fd(int fd, char *msg);

/**
 * <pre>
 * Writes a message to a FIFO pipe
 * </pre>
 *
 * @param[in] pipe The FIFO pipe name
 * @param[in] msg Message to be sent along the pipe, null-terminated
 *
 * @return 0 if success, 1 if error
 */
  int write_to_pipe(char *pipe, char *msg);

/**
 * <pre>
 * Reads a message from the FIFO pipe
 * </pre>
 *
 * @param[in] pipe The FIFO pipe name
 * @param[out] msg Message sent along the pipe
 *
 * @return 0 if success, 1 if error
 */
  int read_from_pipe(char *pipe, char **msg);

/**
 * <pre>
 * Reads a complete message from the interface FIFO pipe
 * </pre>
 *
 * @param[in] fd The FIFO pipe file descriptor number
 *
 * @return 0 if success, 1 if error
 */
  int read_listener(int fd);

/**
 * <pre>
 * Splits a message on the pelz pipe into tokens. Assumes a delimiter of ' '
 * </pre>
 *
 * @param[out] Reference to a double pointer intended to hold tokens
 * @param[out] The number of tokens output
 * @param[in]  The message to be tokenized
 * @param[in]  The length of the message being tokenized
 *
 * @return 0 if success, 1 if error
 */
  int tokenize_pipe_message(char ***tokens, size_t * num_tokens, char *message, size_t message_length);

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

/**
 * <pre>
 * Opens a FIFO pipe for reading
 * </pre>
 *
 * @param[in] name The FIFO pipe name
 *
 * @return the pipe's file descriptor number if success, -1 if error
 */
  int open_read_pipe(char *name);

/**
 * <pre>
 * Opens a FIFO pipe for writing
 * </pre>
 *
 * @param[in] name The FIFO pipe name
 *
 * @return the pipe's file descriptor number if success, -1 if error
 */
  int open_write_pipe(char *name);

/**
 * <pre>
 * Removes a FIFO pipe
 * </pre>
 *
 * @param[in] name The FIFO pipe name
 *
 * @return 0 if success, 1 if error
 */
  int remove_pipe(char *name);

#ifdef __cplusplus
}
#endif

#endif
