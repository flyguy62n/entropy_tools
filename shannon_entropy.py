#!/usr/bin/python3

import argparse
import csv
import math
import sys
import textwrap

from functools import partial


def commandLineParser() -> argparse.ArgumentParser:
    '''Handles the command line options'''
    parser = argparse.ArgumentParser(
    prog=sys.argv[0].split('/')[-1],
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''
        Calculate the Shannon entropy of a string or file

        Calculating Entropy:
            * A file can provided containing the values.  Entropy will be computed for blocks of the file.  See INPUT section below.
            * The file will be read as binary data.
            * If no file is provided, the program will ask the user for input.
                                
        Reviewing Results:
            * Use the CSV output to plot the entropy of each block.
            * Take note of interesting blocks and add them (one per line) to a text file.
            * Use the "-r | --review-file" option.
            * The content of those blocks will be output to the screen.
            * Be sure to use the same Window Offset and Block Size as the original analysis or else the content won't line up.
        
        ''')
    )

    inputControl = parser.add_argument_group(title='Input')
    inputControl.add_argument(
        '-if', '--in-file',
        dest='inputFile',
        default='',
        help='File to read the values from',
    )
    inputControl = parser.add_argument(
        '-b', '--block-size',
        dest='blockSize',
        type=int,
        default=32,
        help='Size of each block to read from the file',
    )
    inputControl = parser.add_argument(
        '-w', '--window-offset',
        dest='windowOffset',
        type=int,
        default=16,
        help='Offset to move the read window by each iteration'
    )

    outputControl = parser.add_argument_group(title='Output')
    outputControl.add_argument(
        '-of', '--out-file',
        dest='outputFile',
        default='',
        help='CSV file to write the results to',
    )
    outputControl = parser.add_argument(
        '-v', '--verbose',
        dest='verbose',
        action='count',
        default=0,
        help='Print each block''s entropy to the screen',
    )
    
    return parser.parse_args()

# Entopy calcs scraped shamelessly from https://stackoverflow.com/questions/2979174/how-do-i-compute-the-approximate-entropy-of-a-bit-string
# The rest is orginal to FlyGuy62n

def entropy(string) -> float:
    "Calculates the Shannon entropy of a string"

    # get probability of chars in string
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]


    # calculate the entropy
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

    return entropy


def entropy_ideal(length):
    "Calculates the ideal Shannon entropy of a string with given length"

    prob = 1.0 / length

    return -1.0 * length * prob * math.log(prob) / math.log(2.0)


def main():
    args=commandLineParser()
    print(args)

    if args.inputFile:
        chunk_count = 0
        results = []
        with open(args.inputFile, 'rb') as inFile:
            for block in iter(partial(inFile.read, args.blockSize), b''):
                result = entropy(block)
                if args.verbose:
                    print (f'Chunk {chunk_count:>6} entropy: {result:.5f} / {entropy_ideal(len(block)):2f}\t{block}')
                if args.outputFile:
                    results.append({
                        'filename': args.inputFile,
                        'chunk_num': chunk_count,
                        'shannon_entropy': result,
                        'ideal_entropy': entropy_ideal(len(block)),
                        'block_size': len(block),
                        'content': block,
                    })
                # If we've reached the end of the file, we'll have a short block and go ahead and stop
                if len(block) < args.blockSize:
                    break
                chunk_count += args.windowOffset
                inFile.seek(chunk_count, 0)
        if args.outputFile:
            with open(args.outputFile, 'w', newline='') as csvfile:
                fieldNames=['filename', 'chunk_num', 'shannon_entropy', 'ideal_entropy', 'block_size', 'content']
                writer = csv.DictWriter(csvfile, fieldnames=fieldNames)
                writer.writeheader()
                for result in results:
                    writer.writerow(result)
            print(f'Results written to {args.outputFile}')
    else:    
        while True:
            try:
                s = input('Enter a string (or CTRL-C to quit): ')
            except KeyboardInterrupt:
                sys.exit()

            print(f'String length  : {len(s)}')
            print(f'Shannon entropy: {entropy(s)}')
            print(f'Ideal entropy  : {entropy_ideal(len(s))}')
        
    
if __name__=='__main__':
    main()