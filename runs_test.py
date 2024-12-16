#!/bin/python3

# From https://www.geeksforgeeks.org/runs-test-of-randomness-in-python/

import argparse
import random
import math
import statistics
import sys
import textwrap

def commandLineParser() -> argparse.ArgumentParser:
    '''Handles the command line options'''
    parser = argparse.ArgumentParser(
    prog=sys.argv[0].split('/')[-1],
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''
        Calculate the Z Statistic of a list of values to determine their randomness

        NOTES:
            * A plaintext file can provided containing the values.
            * If none is provided, the program will create random values using Python's random.random() function.
            * Non-numeric lines will be ignored
        ''')
    )

    inputControl = parser.add_argument_group(title='Input')
    inputControl.add_argument(
        '-f', '--file',
        dest='inputFile',
        default='',
        help='File to read the values from',
        )
    
    return parser.parse_args()

def runsTest(l, ):
    runs_observed, n1, n2 = 0, 0, 0

    l_median = statistics.median(l)

    # Check for the start of new run
    for i in range(len(l)):
        # no. of runs
        if (l[i] >= l_median and l[i-1] < l_median) or (l[i] < l_median and l[i-1] >= l_median):
            runs_observed += 1

        # no. of positive runs
        if (l[i] >= l_median):
            n1 += 1

        # no. of negative runs
        else:
            n2 += 1

    runs_expected = ((2*n1*n2) / (n1+n2)) + 1
    standard_dev = math.sqrt((2*n1*n2*(2*n1*n2-n1-n2)) / (((n1+n2)**2)*(n1+n2-1)))

    z = (runs_observed - runs_expected) / standard_dev

    return z

def main():
    l = []
    args=commandLineParser()

    if not args.inputFile:
        while True:
            try:
                length = int(input("How many entries to test against (or CTRL-C to quit): "))
            except ValueError:
                print("Integers only!")
                continue
            except KeyboardInterrupt:
                print("\nDone!")
                sys.exit()

            for _ in range(length):
                l.append(random.random())
            
            Z = abs(runsTest(l))

            print('Z-Statistic = ', Z)
    else:
        with open(args.inputFile) as f:
            lines = f.readlines()
            for line in lines:
                line = line.rstrip()
                try:
                    l.append(float(line))
                except ValueError:
                    print('Non-numeric value ignored: ', line)

        if l:            
            print('Sample size: ', len(l))
            Z = abs(runsTest(l))

            print('Z-Statistic = ', Z)
        else:
            print('Empty list!')

if __name__=='__main__':
    main()