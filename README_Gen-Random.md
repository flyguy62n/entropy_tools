# Generate Random Data

## Description
I wrote this utility because I needed a way to create random data that I could use to become familiar with the [NIST Statistical Test Suite](https://github.com/arcetri/sts) as part of a project.

## Features
It generates random data using the Python `os.urandom()` method, which should in turn get its random data from the underlying OS.
* If run naked, it will generate one file of 4,096 x 32-byte random binary data and write the result to `bin.out`.  You should recognize 32-bytes as the equivalent of one AES-256 key.
* Other options have been added to support specific project requirements that have arisen.  For instance:
    * An option to generate a SHA-256 hash as the random data that is based on a random 32-byte key PLUS the unique Machine GUID, as a customer was using this method to generate their encryption keys and I wanted to see if it hurt the randomness of the key.
    * Specify the number of random files to create as well as the size of the blocks and the number of blocks in each file.
    * Maybe I'll add options for KDFs such as `Argon2`, `PBKDF2` or `scrypt` in the future.

Use `gen-random.py --help` to see all of the available options.

## Installation
1. Clone the repository: `git clone https://github.com/flyguy62n/entropy_tools.git`
2. Navigate to the project directory: `cd entropy_tools`
3. (Optional) Create a Python virtual environemt: `python3 -m venv .venv`
4. (Optional) Activate the VENV: (Linux/MacOS) `source .venv/bin/activate` or (Windows PS) `.venv/Scripts/activate.ps1`
5. Install the requirements: `pip install -r requirements-gen_random.txt`

## Usage
1. Activate the VENV (if not already activated): (Linux/MacOS) `source .venv/bin/activate` or (Windows PS) `.venv/Scripts/activate.ps1`
2. Run the tool: `python gen_random.py --help`
3. Deactivate the VENV when done (or just close the shell prompt): `deactivate`

### Analysis and Review
1. Use the NIST STS (such as available [here](https://github.com/arcetri/sts)) to parse the binary file: `sts bin.out`
2. Review the `result.txt` file

## Contributing
Contributions are welcome! If you have any suggestions or improvements, please open an issue or submit a pull request.

## License
This project is licensed under the [MIT License](LICENSE).

## Contact
For any questions or inquiries, please contact me.
