/*
 * cmd_interface.c
 */
#include <stdbool.h>
#include <string.h>

#include "pelz_log.h"
#include "cmd_interface.h"

CmdArgValue check_arg(char *arg)
{
  //Checking for value in arg
  if (arg == NULL)
  {
    return EMPTY;
  }

  //Checking for seal command
  if ((memcmp(arg, "seal", 4) == 0) && (strlen(arg) == 4))
  {
    return SEAL;
  }

  //Checking for exit command then execution
  if ((memcmp(arg, "exit", 4) == 0) && (strlen(arg) == 4))
  {
    return EX;
  }

  //Checking for keytable command
  if ((memcmp(arg, "keytable", 8) == 0) && (strlen(arg) == 8))
  {
    return KEYTABLE;
  }

  //Checking for pki command
  if ((memcmp(arg, "pki", 3) == 0) && (strlen(arg) == 3))
  {
    return PKI;
  }

  //Checking for remove command
  if ((memcmp(arg, "remove", 6) == 0) && (strlen(arg) == 6))
  {
    return REMOVE;
  }

  //Checking for keytable list command
  if ((memcmp(arg, "list", 4) == 0) && (strlen(arg) == 4))
  {
    return LIST;
  }

  //Checking for pki load command
  if ((memcmp(arg, "load", 4) == 0) && (strlen(arg) == 4))
  {
    return LOAD;
  }

  //Checking for pki cert command
  if ((memcmp(arg, "cert", 4) == 0) && (strlen(arg) == 4))
  {
    return CERT;
  }

  //Checking for private command
  if ((memcmp(arg, "private", 7) == 0) && (strlen(arg) == 7))
  {
    return PRIVATE;
  }

  return OTHER;        
}
