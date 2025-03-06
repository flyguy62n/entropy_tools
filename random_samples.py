#!/bin/env python3

import argparse
import random
import sys

def commandLineParser() -> argparse.ArgumentParser:
    '''Handles the command line options'''

    parser=argparse.ArgumentParser(
        prog=sys.argv[0].split('/')[-1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=('''
            Create random samples from a range of numbers
            ''')
    )

    configControl = parser.add_argument_group('Configuration')
    configControl = parser.add_argument(
        '--low',
        dest='low_limit',
        default=0,
        type=int,
        help='The low limit (inclusive) to pick samples from (default = 0)'
    )
    configControl = parser.add_argument(
        '--high', 
        dest='high_limit',
        default=100,
        type=int,
        help='The high limit (inclusive) to pick samples from (default = 100)'
    )
    configControl = parser.add_argument(
        '--sample-size',
        dest='sample_size',
        default=10,
        type=int,
        help='The sample size to pick (default = 10)'
    )
    configControl = parser.add_argument(
        '-1', '--one-line',
        dest='one_line',
        action='store_true',
        help='Print the results as one-per-line (default is comma-separated list)'
    )

    return parser.parse_args()

def main():
    config = commandLineParser()
    print(config)

    samples=set()

    while len(samples) < config.sample_size:
        samples.add(random.randint(config.low_limit, config.high_limit))

    samples=sorted(samples)

    if config.one_line:
        for i, sample in enumerate(samples):
            print(f'{i+1}: {sample}')
    else:
        print(sorted(samples))


if __name__== '__main__':
    main()