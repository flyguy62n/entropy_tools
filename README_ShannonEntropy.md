# Shannon Entropy Calculator

## Description
I wrote this utility because I needed a way to find embedded-but-random content in application source code.  Maybe a hard-coded X.509 certificate or an AES-256 key.  Stuff like that.

## Features
It computes Shannon Entropy (as in Claude Shannon) on bytes.  
* If run naked, it will ask for user input.  Human language (or at least English) will produce a Shannon Entropy of somewhere in the low-to-mid 2's.
* It will also read a file - binary, text, doesn't matter.  In that case, there are more options available to tune the analysis.  Notably:
    * Block Size -- How much data to process at once.  That is, how big is the buffer.
    * Window Offset -- How much to move the buffer each time.
    * Input and output file paths
* Write a CSV file with the results.
    * Try charting the 'chunk_count' and 'shannon_entropy' fields as a line chart in Excel
    * You should be able to spot outliers
    * Add the noted chunks to a "review file" and use the tool again to output just those blocks to the screen


## A Note About Shannon Entropy
Entropy is really the measure of randomness -- or an indication of the "unknowable."  Try searching YouTube for "Shannon Entropy" and watch a couple of videos.

With the default block size of 32 bytes, the "Ideal Entropy" is 5 (2^^5 = 32).

On that note, from my own testing using some PowerShell scripts, /dev/random output, and Python source code anthing over about a 4.3 is interesting and north of 4.5 is probably completely random.  In that case, you've probably found a digital signature, a crypto key or some other interesting content.

## Installation
1. Clone the repository: `git clone https://github.com/flyguy62n/entropy_tools.git`
2. Navigate to the project directory: `cd entropy_tools`

## Usage
1. Run the Shannon Entropy tool: `python shannon_entropy.py --help`

### Analysis and Review
Try this:
1. `python shannon-entropy.py --in-file <path/to/file> --out-file <path/to/file>.csv`
2. Review the CSV file in Excel.  Plot a chart using `chunk_num` and `shannon_entropy`
3. Take note of any interesting spikes
4. Add to the `chunk_num` to `review_blocks.txt` (one entry per line)
5. `python shannon-entropy.py --in-file <path/to/file> --review-file review_blocks.txt`
6. Confirm / reject the suspicious content
7. Revel in your new-found ability to find embedded, random text

Notes:
* Depending on the nature of the secrets you're looking for, you might need to tune the searches
* X.509 certificates are pretty long, so the defaults are probably fine.
* AES Encryption Keys are comparitively shorter, so consider:
    * The default `--block-size` of 32 bytes is probably fine since for AES-256 keys (that's 32 bytes)
    * Consider reducing the `--window-offset` to 8, 4, or even 1 byte.  This is because if you go barreling through the file, you could accidentally split the AES key into 2 parts, which might "hide" it amongst the other content and you'd miss the spike.  With a smaller `--window-offset`, you'll get fine resolution and be more likely (absolutely certain if it's 1 byte) to capture the entire key in one block.
    * In this scenario, you'll see the entropy ramp up and then back down again (bell-shaped curve) when you chart it in Excel

## Contributing
Contributions are welcome! If you have any suggestions or improvements, please open an issue or submit a pull request.

## License
This project is licensed under the [MIT License](LICENSE).

## Contact
For any questions or inquiries, please contact me.
