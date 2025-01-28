#!/bin/env python3

import argparse
import os
import sys

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
        '-n', '--num-blocks',
        dest='num_blocks',
        default='4096',
        type=int,
        help='Number of blocks to create (def=4096)',
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
        help='Print byte content to STDOUT as well'

    )
    
    return parser.parse_args()

def main():
    args=commandLineParser()
    with open(args.filename, "wb") as f:
        for i in range(args.num_blocks):
            key = os.urandom(args.blocksize)
            f.write(key)
            if args.verbose:
                print(f'Index [{i+1}]: {str(key)}')
    print(f'Content written to {args.filename}')

if __name__ == "__main__":
    main()