#ifndef _INTERFACE_H_
#define _INTERFACE_H_

typedef enum
{ CMD_ENCRYPT,
  CMD_DECRYPT,
} CmdType;

typedef enum
{ EMPTY,    //NULL value
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

#endif
