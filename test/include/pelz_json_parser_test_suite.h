/*
 * pelz_json_parser_suite.h
 */

#ifndef PELZ_JSON_PARSER_SUITE_H_
#define PELZ_JSON_PARSER_SUITE_H_

#include "pelz_request_handler.h"
#include "pelz_json_parser.h"
#include <CUnit/CUnit.h>

// Adds all tests to key table suite in main test runner
int pelz_json_parser_suite_add_tests(CU_pSuite suite);

// Tests
void test_request_decoder(void);
void test_message_encoder(void);
void test_error_message_encoder(void);

#endif /* PELZ_JSON_PARSER_SUITE_H_ */
