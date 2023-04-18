#!/bin/bash

# Attestation demo setup script

function decode_json
{
    python3 -c "import json; import sys; print(json.load(sys.stdin).get('$1'))" <<<"""$2"""
}


PELZ_HOST=localhost
PELZ_PORT=10600
KEY_BYTES=32
OUT_DIR=$(readlink -f test_data)
KEK_FILE="${OUT_DIR}/attdemo_kek.txt"
ORIG_DEK_FILE="${OUT_DIR}/attdemo_dek_orig.txt"
ENC_DEK_FILE="${OUT_DIR}/attdemo_dek_wrapped.txt"
ORIG_DATA_FILE="${OUT_DIR}/attdemo_data_orig.txt"
ENC_DATA_FILE="${OUT_DIR}/attdemo_data_enc.txt"

mkdir -p "${OUT_DIR}"

# 1. Create a random symmetric KEK (key encryption key).

head -c "${KEY_BYTES}" /dev/urandom >"${KEK_FILE}"

# 2. Create a formatted data file. (The worker enclave should only operate on files with a specific format.)

# Currently using placeholder data.
# TODO: Save a data file in the repo instead.
echo -n "abcdefghijklmnopqrstuvwx" >"${ORIG_DATA_FILE}"

# 3. Encrypt the file with the DEK.

# Note: pelz must be invoked from the top repo directory because it uses a hard-coded path to the enclave file.
# This command creates KEY, KEY_IV, and KEY_TAG files in the current directory, although that behavior will likely change.
# The KEY file is the randomly-generated DEK (data encryption key).
pushd ..
bin/pelz encrypt "${ORIG_DATA_FILE}" -o "${ENC_DATA_FILE}"
mv KEY "${ORIG_DEK_FILE}"
popd

# 4. Call pelz to wrap the DEK with the KEK.

# Note: Wrap request data must be base64, with original length a multiple of 8 characters, and ending with a newline.
# Also remember that keys are only loaded from a file if they're not already stored in pelz.

WRAP_REQ="""{\"key_id\": \"file:${KEK_FILE}\", \"request_type\": 1, \"cipher\": \"AES/KeyWrap/RFC3394NoPadding/128\", \"data\": \"$(base64 -w 0 "${ORIG_DEK_FILE}")\n\"}"""
echo "${WRAP_REQ}"

WRAP_RESP=$(ncat "${PELZ_HOST}" "${PELZ_PORT}" <<<"${WRAP_REQ}")
echo "${WRAP_RESP}"

decode_json "data" "${WRAP_RESP}" | base64 -d -w 0 >"${ENC_DEK_FILE}"

# 5. Initiate the worker client with the following command line arguments: path to encrypted file; path to encrypted DEK; path to KEK

CMD="bin/appinitiator ${ENC_DATA_FILE} ${ENC_DEK_FILE} ${KEK_FILE}"
echo "${CMD}"
${CMD}
