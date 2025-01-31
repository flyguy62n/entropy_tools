#!/bin/env python3

import argparse
import hashlib
import os
import sys

try:
    import machineid 
except ModuleNotFoundError:
    print ('py-machineid module not found.  Do you need to activate a VENV or maybe install it with:\n')
    print ('\tpip install -r requirements-gen_random.txt')
    sys.exit(1)


def commandLineParser() -> argparse.ArgumentParser:
    '''Handles the command line options'''
    parser = argparse.ArgumentParser(
    prog=sys.argv[0].split('/')[-1],
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=('''
        Create random data using Python's os.random() method.  Useful to test using the NIST Statistical Test Suite (https://github.com/arcetri/STS/)
                 
        NOTES:
            * In the default configuration, STS requires 131072 bytes of data to work with.  This is 4,096 blocks of 32 bytes each (e.g. AES-256 keys)
        ''')
    )

    configControl = parser.add_argument_group(title="Configuration")
    configControl.add_argument(
        '-s', '--block-size',
        dest='blocksize',
        default='32',
        type=int,
        help='Size of an individual block (def=32, e.g. for AES-256)',
        )
    configControl.add_argument(
        '-b', '--blocks',
        dest='num_blocks',
        default='4096',
        type=int,
        help='Number of blocks to create (def=4096)',
    )
    configControl.add_argument(
        '-g', '--machine-guid',
        dest='machine_id',
        action='store_true',
        help='Use the Machine ID as a pepper along with SHA-256 when generating keys',
    )
    configControl.add_argument(
        '-n', '--num-files',
        dest='num_files',
        type=int,
        default=1,
        help='Number of files to create',
    )
    configControl.add_argument(
        '-f', '--out-file',
        dest='filename',
        default='bin.out',
        help='Binary output file to create (def=bin.out)',
        )
    configControl.add_argument(
        '-v', '--verbose',
        dest='verbose',
        action='store_true',
        help='Print byte content to STDOUT as well',
    )
    
    return parser.parse_args()

def main():
    args=commandLineParser()
    print(args)
    if args.machine_id:
        print('Using Machine ID to pepper the key for SHA-256')
        m_id=bytes(machineid.id(), 'utf-8')
    for file_count in range (args.num_files):
        if args.filename.find('.') > -1:                                # If the file name includes a period
            filename_parts = args.filename.split('.')
            filename_parts[-2] = f'{filename_parts[-2]}_{file_count}'   # Append an _# to the second-to-last part of the file (the last part before the final .ext)
            filename = '.'.join(filename_parts)                         # Re-join the file parts with dots
        else:
            filename = f'{args.filename}_{file_count}'
        with open(filename, "wb") as f:
            for i in range(args.num_blocks):
                key = os.urandom(args.blocksize)
                if args.machine_id:
                    key=hashlib.sha256(m_id+key).digest()               # Use a SHA-256 of the random key and the Machine GUID as the key
                f.write(key)
                if args.verbose:
                    print(f'Index [{i+1}]: {str(key)}')
        print(f'Content written to {filename}')

if __name__ == "__main__":
    main()