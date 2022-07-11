/*
 * request_signing_test_suite.h
 */

#ifndef PELZ_REQUEST_SIGNING_SUITE_H_
#define PELZ_REQUEST_SIGNING_SUITE_H_

#include "request_signing.h"
#include <CUnit/CUnit.h>

// Adds all tests to suite in main test runner
int request_signing_suite_add_tests(CU_pSuite suite);

// Tests
void test_create_validate_signature_simple(void);
void test_create_validate_signature(void);
void test_verify_cert_chain(void);
void test_verify_cert_chain_enclave(void);

#endif /* PELZ_REQUEST_SIGNING_SUITE_H_ */
