#ifndef ENCRYPT_DATATYPES_H_
#define ENCRYPT_DATATYPES_H_

#define IV_SIZE 12
#define TAG_SIZE 16
#define KEY_SIZE 32
#define KEY_SIZE_WRAPPED 40
#define KEK_ID_SIZE 128

/* This struct is used as an encrypted data file format. */
typedef struct __attribute__ ((__packed__)) encrypt_file_content {
  uint8_t format_code[8];
  char kek_id[KEK_ID_SIZE];
  uint8_t wrapped_key[KEY_SIZE_WRAPPED];
  uint8_t iv[IV_SIZE];
  uint8_t tag[TAG_SIZE];
  uint8_t cipher_data[];
} encrypt_file_content;

/* This struct is used for passing related data to encrypt/decrypt ECALLs. */
typedef struct encrypt_bundle {
  uint8_t key[KEY_SIZE];
  uint8_t iv[IV_SIZE];
  uint8_t tag[TAG_SIZE];
  uint8_t cipher_data[];
} encrypt_bundle;

#endif