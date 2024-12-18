# Shannon Entropy Calculator

## Description
I wrote this utility because I needed a way to find embedded-but-random content in application source code as part of software security audits.  Maybe a hard-coded X.509 certificate or an AES-256 key.  Stuff like that.

## Features
It computes Shannon Entropy (as in Claude Shannon) on bytes.  
* If run naked, it will ask for user input.  Human language (or at least English) will produce a Shannon Entropy of somewhere in the low-to-mid 2's.
* It will also read a file - binary, text, doesn't matter.  In that case, there are more options available to tune the analysis.  Notably:
    * Block Size -- How much data to process at once.  That is, how big is the buffer.
    * Window Offset -- How much to move the buffer each time.
    * Input and output file paths

## A Note About Shannon Entropy
Entropy is really the measure of randomness -- or an indication of the "unknowable."  Try searching YouTube for "Shannon Entropy" and watch a couple of videos.

With the default block size of 32 bytes, the "Ideal Entropy" is 5 (2^^5 = 32).

On that note, from my own testing using some PowerShell scripts, /dev/random output, and Python source code anything over about a 4.3 is interesting and north of 4.5 is probably completely random.  In that case, you've probably found a digital signature, a crypto key or some other interesting content.

Interestingly, P-Boxes and S-Boxes used in encryption ciphers like AES apear to have notably lower entropy than the source code around them -- in the lower 3s where the surround source code ranges in the upper 3s and lower 4s.  It just goes to show that both higher and lower entropy could be interesting things to look at further.

## Installation
1. Clone the repository: `git clone https://github.com/flyguy62n/entropy_tools.git`
2. Navigate to the project directory: `cd entropy_tools`

## Usage
1. Run the Shannon Entropy tool: `python shannon_entropy.py --help`

### Analysis and Review
Try this:
1. Run `python shannon-entropy.py --in-file <path/to/file> --out-file <path/to/file>.csv`
2. Review the CSV file in Excel.  
3. Plot a scatter chart using `chunk_num` and `shannon_entropy`.
4. Take note of any interesting peaks and valleys.
7. Confirm / reject the suspicious content.
8. Revel in your new-found ability to find apply entropy analysis to your source code.

Notes:
* Depending on the nature of the secrets you're looking for, you might need to tune the searches
    * The defaults are `--block-size=32` and `--windows-offset=16`
    * 32 bytes of data will be analyzed at a time with a 16-byte overlap
* X.509 certificates are pretty long, so the defaults are probably fine.
* AES Encryption Keys are comparitively shorter, so consider:
    * The default `--block-size` of 32 bytes is probably fine since for AES-256 keys (that's 32 bytes), but you might need to change it for AES-128 keys.
    * Consider reducing the `--window-offset` to 8, 4, or even 1 byte.  This is because if you go barreling through the file, you could accidentally split the AES key into 2 parts, which might "hide" it amongst the other content and you'd miss the spike.  With a smaller `--window-offset`, you'll get fine resolution and be more likely (absolutely certain if it's 1 byte) to capture the entire key in one block.
    * In this scenario, you'll see the entropy ramp up and then back down again (bell-shaped curve) when you chart it in Excel
* Big changes in entropy from the nearby content are probably interesting:
    * An embedded AES-256 key should have higher entropy.  See the notes above about turning the parameters to improve the chances you'll see them.
    * A digital signature is hard to miss as they're both long (1,000s of bytes) and random.  You'll see a big block of higher-entropy content than what surrounds it.
    * From my own testing, substitition and/or permutation boxes used in many encryption ciphers could have lower entropy than the source code around it.

## Contributing
Contributions are welcome! If you have any suggestions or improvements, please open an issue or submit a pull request.

## License
This project is licensed under the [MIT License](LICENSE).

## Contact
For any questions or inquiries, please contact me.
