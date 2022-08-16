#ifndef _PELZ_CA_TABLE_H_
#define _PELZ_CA_TABLE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <openssl/x509.h>

bool validate_cert(X509* cert);


#ifdef __cplusplus
}
#endif

#endif
