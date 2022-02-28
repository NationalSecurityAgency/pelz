#ifndef _CMD_INTERFACE_PELZ_H_
#define _CMD_INTERFACE_PELZ_H_

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
  OTHER     //Non-null vlue other then the ones listed above
}CmdArgValue;

/**
 * @brief Checks the command line argument for valid command entry
 *
 * @param[in]   arg  The command line argument to be validated
 *
 * @returns CmdArgValue
 */
  CmdArgValue check_arg(char *arg);

#endif
