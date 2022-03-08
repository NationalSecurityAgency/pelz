/*
 * cmd_interface.c
 */
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "cmd_interface.h"
#include "pelz_log.h"
#include "pelz_io.h"

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

  return OTHER;        
}

int msg_arg(char *pipe, int pipe_len, int cmd, char *arg, int arg_len)
{
  char *msg = (char *) calloc((8 + pipe_len + arg_len), sizeof(char));
  sprintf(msg, "pelz %d %.*s %.*s", cmd, pipe_len, pipe, arg_len, arg);
  pelz_log(LOG_DEBUG, "Message: %s", msg);
  write_to_pipe((char*) PELZSERVICE, msg);
  free(msg);
  if (read_listener(pipe))
  {
    pelz_log(LOG_DEBUG, "Error read from pipe.");
    return 1;
  }
  return 0;
}

int msg_list(char *pipe, int pipe_len, int cmd)
{
  char *msg = (char *) calloc((8 + pipe_len), sizeof(char));
  sprintf(msg, "pelz %d %.*s", cmd, pipe_len, pipe);
  pelz_log(LOG_DEBUG, "Message: %s", msg);
  write_to_pipe((char*) PELZSERVICE, msg);
  free(msg);
  do
  {
    if (read_listener(pipe))
    {
      break;
    }
  } while (1);
  return 0;
}
