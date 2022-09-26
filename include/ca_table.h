#ifndef _PELZ_CA_TABLE_H_
#define _PELZ_CA_TABLE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <openssl/x509.h>

  
int validate_cert(X509* cert);


#ifdef __cplusplus
}
#endif

#endif
