#!/usr/bin/env python3

# Attestation demo setup script

import os
import secrets
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

    # 1. Generate asymmetric keys for the client

    cmd = ['../make_certs.sh']
    print_log('Generating asymmetric keys ...')
    print_log(' '.join([str(x) for x in cmd]) + '\n')
    subprocess.run(cmd, check=True, cwd=OUT_DIR)
    print()

    # 2. Seal the CA cert and register with pelz

    cmd = [
        'bin/pelz',
        'seal',
        OUT_DIR / 'ca_pub.der',
        '-o', OUT_DIR / 'ca_pub.der.nkl',
    ]
    print_log('Sealing CA cert ...')
    print_log(' '.join([str(x) for x in cmd]) + '\n')
    subprocess.run(cmd, check=True, cwd=DEMO_DIR.parent)
    print()

    cmd = [
        'bin/pelz',
        'pki', 'load', 'cert',
        OUT_DIR / 'ca_pub.der.nkl',
    ]
    print_log('Registering CA cert ...')
    print_log(' '.join([str(x) for x in cmd]) + '\n')
    subprocess.run(cmd, check=True, cwd=DEMO_DIR.parent)
    print()

    # 3. Create a random symmetric KEK (key encryption key).

    with open(KEK_FILE, 'wb') as f:
        f.write(secrets.token_bytes(KEY_BYTES))

    # 4. Create a text file representing application data.

    # Currently using placeholder data.
    # TODO: Possibly save a data file in the repo instead.
    with open(ORIG_DATA_FILE, 'w') as f:
        f.write('placeholder data\nabcdefghijklmnopqrstuvwxyz')

    # 5. Use the worker client to encrypt the file and wrap the generated DEK.

    cmd = [
        'bin/demo_worker',
        'encrypt',
        f'file:{KEK_FILE}',
        '-i', ORIG_DATA_FILE,
        '-o', ENC_DATA_FILE,
    ]
    print_log('Encrypting the data file using the demo client ...')
    print_log(' '.join([str(x) for x in cmd]) + '\n')
    subprocess.run(cmd, check=True, cwd=DEMO_DIR)
    print()

    # 6. Use the worker client to decrypt and search the file within the enclave.

    cmd = [
        'bin/demo_worker',
        'search',
        'abcd',  # search term
        '-i', ENC_DATA_FILE,
    ]
    print_log('Decrypting and searching the data file using the demo client ...')
    print_log(' '.join([str(x) for x in cmd]) + '\n')
    subprocess.run(cmd, check=True, cwd=DEMO_DIR)


if __name__ == '__main__':
    main()
