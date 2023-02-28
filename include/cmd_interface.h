#ifndef _CMD_INTERFACE_PELZ_H_
#define _CMD_INTERFACE_PELZ_H_

#include <stddef.h>

/*
 *  0    seal <path>               Seals a file in .nkl format (pelz-service is not involved)
 *  1    exit                      Terminates running pelz-service
 *  2    keytable remove <key>     Removes a key with a specified <id>
 *  3    keytable remove --all     Removes all keys
 *  4    keytable list             Outputs a list of key <id> in Key Table
 *  5    pki load cert <path>      Loads a server certificate
 *  6    pki load private <path>   Loads a private key for connections to key servers
 *  7    pki cert list             Outputs a list of certificate <CN> from the Server Table
 *  8    pki remove <CN>           Removes a server certificate
 *  9    pki remove --all          Removes all server certificates
 *  10   pki remove private        Removes the private key
 *  11   ca load <path>            Loads a CA certificate
 *  12   ca list                   Outputs a list of certificate <CN> from the CA Table
 *  13   ca remove <CN>            Removes a CA certificate
 *  14   ca remove --all           Removes all CA certificates
 */
typedef enum
{ CMD_SEAL = 0,
  CMD_EXIT,
  CMD_REMOVE_KEY,
  CMD_REMOVE_ALL_KEYS,
  CMD_LIST_KEYS,
  CMD_LOAD_CERT,
  CMD_LOAD_PRIV,
  CMD_LIST_CERTS,
  CMD_REMOVE_CERT,
  CMD_REMOVE_ALL_CERTS,
  CMD_REMOVE_PRIV = 10,
  CMD_LOAD_CA,
  CMD_LIST_CA,
  CMD_REMOVE_CA,
  CMD_REMOVE_ALL_CA,
  CMD_ENCRYPT,
  CMD_DECRYPT,
} CmdType;

typedef enum
{ EMPTY,    //NULL value
  SEAL,     
  EX,       //Exit     
  KEYTABLE, 
  PKI,      
  REMOVE,   
  LIST,     
  LOAD,     
  CERT,     
  PRIVATE,  
  CA,
  ENC,
  DEC,
  OTHER     //Non-null value other then the ones listed above
}CmdArgValue;

/**
 * @brief Checks the command line argument for valid command entry
 *
 * @param[in]   arg  The null-terminated command line argument to be validated
 *
 * @returns CmdArgValue
 */
  CmdArgValue check_arg(char *arg);

/**
 * @brief Creates and sends message then listens for response on the pipe provided.
 *        Message includes an agrument to be passed to the service.
 *
 * @param[in]   pipe      The pipe to receive a response on
 * @param[in]   pipe_len  The character length of the pipe value
 * @param[in]   cmd       The value of the command to be sent on the pipe
 * @param[in]   arg       The command line argument to sent on the pipe
 * @param[in]   arg_len   The character length of the argument to be sent
 *
 * @returns 0 on success, 1 on error
 */
  int msg_arg(char *pipe, size_t pipe_len, int cmd, char *arg, size_t arg_len);

/**
 * @brief Creates and sends message then listens for response on the pipe provided.
 *        Message includes an argument to be passed to the service.
 *
 * @param[in]   pipe      The pipe to receive a response on
 * @param[in]   pipe_len  The character length of the pipe value
 * @param[in]   cmd       The value of the command to be sent on the pipe
 * @param[in]   arg       The command line argument to be sent on the pipe
 * @param[in]   arg_len   The character length of the argument to be sent
 * @param[in]   arg2      The second command line argument to be sent on the pipe
 * @param[in]   arg2_len  The character length of the second argument to be sent
 *
 * @returns 0 on success, 1 on error
 */
  int msg_two_arg(char *pipe, int pipe_len, int cmd, char *arg, int arg_len, char *arg2, int arg2_len);

/**
 * @brief Creates and sends message then listens for a list of responses on the pipe provided.
 *
 * @param[in]   pipe      The pipe to receive a response on
 * @param[in]   pipe_len  The character length of the pipe value
 * @param[in]   cmd       The value of the command to be sent on the pipe
 *
 * @returns 0 on success, 1 on error
 */
  int msg_list(char *pipe, size_t pipe_len, int cmd);
#endif
