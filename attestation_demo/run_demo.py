#!/usr/bin/env python3

# Attestation demo setup script

import base64
import json
import os
import secrets
import socket
import shutil
import subprocess

from pathlib import Path

KEY_BYTES = 32

SCRIPT_NAME = Path(__file__).name
DEMO_DIR = Path(__file__).parent.absolute()
OUT_DIR = DEMO_DIR / 'test_data'
KEK_FILE = OUT_DIR / 'attdemo_kek.txt'
ORIG_DATA_FILE = OUT_DIR / 'attdemo_data_orig.txt'
ENC_DATA_FILE = OUT_DIR / 'attdemo_data_enc.txt'


def print_log(*args, **kwargs):
    print(f'{SCRIPT_NAME}:', *args, **kwargs)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    # 1. Create a random symmetric KEK (key encryption key).
    with open(KEK_FILE, 'wb') as f:
        f.write(secrets.token_bytes(KEY_BYTES))

    # 2. Create a text file representing application data.

    # Currently using placeholder data.
    # TODO: Possibly save a data file in the repo instead.
    with open(ORIG_DATA_FILE, 'w') as f:
        f.write('placeholder data\nabcdefghijklmnopqrstuvwx')

    # 3. Use the worker client to encrypt the file and wrap the generated DEK.

    cmd = [
        'bin/demo_worker',
        'encrypt',
        ORIG_DATA_FILE,
        ENC_DATA_FILE,
        f'file:{KEK_FILE}',
    ]
    print_log('Encrypting the data file using the demo client ...')
    print_log(' '.join([str(x) for x in cmd]) + '\n')
    subprocess.run(cmd, check=True, cwd=DEMO_DIR)
    print()

    # 5. Use the worker client to decrypt and search the file within the enclave.

    cmd = [
        'bin/demo_worker',
        'search',
        ENC_DATA_FILE,
        'abcd',  # search term
    ]
    print_log('Decrypting and searching the data file using the demo client ...')
    print_log(' '.join([str(x) for x in cmd]) + '\n')
    subprocess.run(cmd, check=True, cwd=DEMO_DIR)


if __name__ == '__main__':
    main()
