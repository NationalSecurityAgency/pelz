#!/bin/env python3

# Attestation demo setup script

import base64
import json
import os
import secrets
import socket
import shutil
import subprocess

from pathlib import Path

PELZ_HOST = 'localhost'
PELZ_PORT = 10600
KEY_BYTES = 32

SCRIPT_NAME = Path(__file__).name
DEMO_DIR = Path(__file__).parent.absolute()
OUT_DIR = DEMO_DIR / 'test_data'
KEK_FILE = OUT_DIR / 'attdemo_kek.txt'
ORIG_DEK_FILE = OUT_DIR / 'attdemo_dek_orig.txt'
ENC_DEK_FILE = OUT_DIR / 'attdemo_dek_wrapped.txt'
ORIG_DATA_FILE = OUT_DIR / 'attdemo_data_orig.txt'
ENC_DATA_FILE = OUT_DIR / 'attdemo_data_enc.txt'


def print_log(*args, **kwargs):
    print(f'{SCRIPT_NAME}:', *args, **kwargs)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    # 1. Create a random symmetric KEK (key encryption key).
    with open(KEK_FILE, 'wb') as f:
        f.write(secrets.token_bytes(KEY_BYTES))

    # 2. Create a formatted data file. (The worker enclave should only operate on files with a specific format.)

    # Currently using placeholder data.
    # TODO: Possibly save a data file in the repo instead.
    with open(ORIG_DATA_FILE, 'w') as f:
        f.write('placeholder data\nabcdefghijklmnopqrstuvwx')

    # 3. Encrypt the file with the DEK.

    # Note: pelz must be invoked from the top repo directory because it uses a hard-coded path to the enclave file.
    # This command creates KEY, KEY_IV, and KEY_TAG files in the current directory, although that behavior will likely change.
    # The KEY file is the randomly-generated DEK (data encryption key).
    cmd = [
        'bin/pelz',
        'encrypt',
        ORIG_DATA_FILE,
        '-o', ENC_DATA_FILE,
    ]
    pelz_dir = DEMO_DIR.parent
    print_log('Using Pelz to encrypt the data file ...')
    print_log(' '.join([str(x) for x in cmd]))
    subprocess.run(cmd, check=True, cwd=pelz_dir)
    shutil.move(pelz_dir / 'KEY', ORIG_DEK_FILE)

    # 4. Call pelz to wrap the DEK with the KEK.

    # Note: Wrap request data must be base64, with original length a multiple of 8 characters, and ending with a newline.
    # Also remember that keys are only loaded from a file if they're not already stored in pelz.

    with open(ORIG_DEK_FILE, 'rb') as f:
        dek_raw = f.read()
    dek_base64 = base64.encodebytes(dek_raw)
    wrap_req = {
        'key_id': f'file:{KEK_FILE}',
        'request_type': 1,
        'cipher': 'AES/KeyWrap/RFC3394NoPadding/128',
        'data': dek_base64.decode(),
    }
    wrap_req_str = json.dumps(wrap_req)
    print_log('Wrapping the DEK ...')
    print_log(f'Pelz key wrap request: {wrap_req_str}')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PELZ_HOST, PELZ_PORT))
        s.send(wrap_req_str.encode())
        wrap_resp_str = s.recv(1024).decode()

    print_log(f'Pelz key wrap response: {wrap_resp_str}')
    wrap_resp = json.loads(wrap_resp_str)
    dek_enc = base64.b64decode(wrap_resp['data'])

    with open(ENC_DEK_FILE, 'wb') as f:
        f.write(dek_enc)

    # 5. Initiate the worker client with the following command line arguments: path to encrypted file; path to encrypted DEK; path to KEK

    cmd = [
        'bin/appinitiator',
        ENC_DATA_FILE,
        ENC_DEK_FILE,
        KEK_FILE,
    ]
    print_log('Running the demo client ...')
    print_log(' '.join([str(x) for x in cmd]) + '\n')
    subprocess.run(cmd, check=True, cwd=DEMO_DIR)


if __name__ == '__main__':
    main()
