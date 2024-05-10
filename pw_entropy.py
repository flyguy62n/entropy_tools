from math import log2, ceil

def calc_entropy(R: int, L: int) -> int:
    return int(log2(R ** L))

def calc_length(E: int, R: int) -> int:
    return ceil(E / log2(R))

if __name__ == '__main__':
    default_R = 92
    
    print('Press CTRL-C to quit')
    choice_prompt='Enter:\n\t"E" to calculate the entropy of a password given symbol range and length\n\t"L" to calculate the required length of a password given symbol range and required Entropy\n'
    choice = input(choice_prompt)

    while True:

        try:
            if choice.lower() == 'e':
                R = int(input(f'Enter the number of possible symbols (default = {default_R}): ') or default_R)
                L = int(input('Enter the length of the password: '))
                print(f'The entropy of the password is: {calc_entropy(R, L)} bits\n')
                
            elif choice.lower() == 'l':
                R = int(input(f'Enter the number of possible symbols (default = {default_R}): ') or default_R)
                E = int(input('Enter the required entropy of the password: '))
                print(f'The length of the password must be at least: {calc_length(E, R)} characters\n')
        except KeyboardInterrupt:
            break
        except ValueError:
            print('Invalid input. Please try again.')
            continue