/*
 * pelz_data_handler.h
 */

#ifndef INCLUDE_PELZ_REQUEST_HANDLER_H_
#define INCLUDE_PELZ_REQUEST_HANDLER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CharBuf.h"

//The maxim key length
#define MAX_KEY_LEN 32
#define MAX_SOC_DATA_SIZE 1024

typedef enum
{ REQ_ENC = 1, REQ_DEC = 2 } RequestType;

typedef enum
{ ASCII = 0, HEX = 1 } FormatType;

typedef enum
{ TXT_F = 1, PEM_F = 2, SOCKET = 3 } LocationType;

typedef enum
{ F_SCHEME = 1, FTP = 2 } SchemeType;

typedef enum
{ TXT_EXT = 1, PEM_EXT = 2, KEY_EXT = 3 } ExtensionType;

typedef struct FILEScheme
{
  CharBuf auth;
  CharBuf path;
  CharBuf f_name;
} FValues;

typedef struct FTPScheme
{
  CharBuf host;
  CharBuf port;
  CharBuf url_path;
} FTPValues;

typedef struct URIParseValues
{
  int type;
  union
  {
    FValues f_values;
    FTPValues ftp_values;
  };
} URIValues;

int pelz_request_handler(RequestType request_type, CharBuf key_id, CharBuf data_in, CharBuf output, CharBuf * message,
  int socket_id);

#endif /* INCLUDE_PELZ_REQUEST_HANDLER_H_ */
