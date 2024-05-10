# Password Entropy Calculator

## Description
This is a simple password entropy calculator that helps you measure the strength of a password based on its complexity and randomness. It calculates the entropy of a password, which is a measure of how difficult it would be to guess the password.

## Features
- Calculates the entropy of a password based on its length and character set.
- Calculates the required length when provided with character set and required entropy

## A Note About Password Entropy
Entropy is really the measure of randomness -- or an indication of the "unknowable."  However, if your password is something like "Fido is my dog2016!", while that's a strong password as measured by length (20) and charactersets (UPPER, lower, numbers, symbols) and will provide a very reasonble 2^128 bits of entropy in most password strength calculators, it's based on knowable facts -- that you have a dog, it's name is Fido, and has been much loved since 2016.  The actual entropy is much, much lower.

The only way to actually achieve 2^128 bits of "unknowable" data is to use a random password.  Which means using a password manager and then securing it with a password that's longer than 20 characters, and using two-step/multi-factor/etc authentication.

## Installation
1. Clone the repository: `git clone https://github.com/flyguy62n/entropy_tools.git`
2. Navigate to the project directory: `cd entropy_tools`

## Usage
1. Run the password entropy calculator: `python pw_entropy.py`
2. Follow the prompts

## Contributing
Contributions are welcome! If you have any suggestions or improvements, please open an issue or submit a pull request.

## License
This project is licensed under the [MIT License](LICENSE).

## Contact
For any questions or inquiries, please contact me.
