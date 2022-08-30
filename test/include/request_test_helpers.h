#ifndef _PELZ_REQUEST_TEST_HELPERS_H_
#define _PELZ_REQUEST_TEST_HELPERS_H_

#include "charbuf.h"
#include "pelz_request_handler.h"
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

charbuf serialize_request_helper(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf data, charbuf iv, charbuf tag, charbuf requestor_cert);

charbuf sign_request(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf data, charbuf iv, charbuf tag, charbuf requerstor_cert, EVP_PKEY* requestor_privkey);

#endif
