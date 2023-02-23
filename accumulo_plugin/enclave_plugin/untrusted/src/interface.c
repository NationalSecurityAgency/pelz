/*
 * cmd_interface.c
 */
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "interface.h"
#include "pelz_log.h"

CmdArgValue check_arg(char *arg)
{
  //Checking for value in arg
  if (arg == NULL)
  {
    return EMPTY;
  }

  /*/Checking for seal command
  if ((memcmp(arg, "seal", 4) == 0) && (strlen(arg) == 4))
  {
    return SEAL;
  }

  //Checking for exit command
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

  //Checking for list command
  if ((memcmp(arg, "list", 4) == 0) && (strlen(arg) == 4))
  {
    return LIST;
  }

  //Checking for load command
  if ((memcmp(arg, "load", 4) == 0) && (strlen(arg) == 4))
  {
    return LOAD;
  }

  //Checking for cert command
  if ((memcmp(arg, "cert", 4) == 0) && (strlen(arg) == 4))
  {
    return CERT;
  }

  //Checking for private command
  if ((memcmp(arg, "private", 7) == 0) && (strlen(arg) == 7))
  {
    return PRIVATE;
  }

  //Checking for ca keyword
  if ((memcmp(arg, "ca", 2) == 0) && (strlen(arg) == 2))
  {
    return CA;
  }*/

  //Checking for encrypt keyword
  if ((memcmp(arg, "encrypt", 7) == 0) && (strlen(arg) == 7))
  {
    return ENC;
  }
 
  //Checking for decrypt keyword
  if ((memcmp(arg, "decrypt", 7) == 0) && (strlen(arg) == 7))
  {
    return DEC;
  }

  return OTHER;        
}
