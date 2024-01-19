import sys, string, secrets, random

#TODO getpass implementation
#TODO automatic copy of password

def random_number(start, end):
    if start >= end:
        raise ValueError("Invalid range")

    return  secrets.randbelow(end - start) + start
def alphabet_generator(count_alphabet):
    upper = list(string.ascii_uppercase)
    lower = list(string.ascii_lowercase)
    alphabet_list = upper + lower
    password_alphabets = [secrets.choice(alphabet_list) for i in range(count_alphabet)]
    return password_alphabets

def number_generator(count_numbers):
    number_list = list(string.digits)
    password_numbers = [secrets.choice(number_list) for i in range(count_numbers)]
    return password_numbers
def symbol_generator(count_symbols):
    symbol_list = list(string.punctuation)
    password_symbols = [secrets.choice(symbol_list) for i in range(count_symbols)]
    return password_symbols
def password_generator(count_alphabet, count_numbers, count_symbols):
    password_alphbets = alphabet_generator(count_alphabet)
    password_numbers = number_generator(count_numbers)
    password_symbols = symbol_generator(count_symbols)
    password_list = password_alphbets + password_numbers + password_symbols
    random.shuffle(password_list)
    password = ''.join(password_list)
    return password

def generate_random_numbers():
    count_alphabet = random_number(1, 10)
    count_numbers = random_number(1, 10)
    count_symbols = random_number(1, 10)
    return count_alphabet, count_numbers, count_symbols
def main():
    minimum = input("How long would you like the password to be at least?")
    if input("Would you like custom password (y/n)?").lower() == 'y':
        count_alphabet = int(input("Give the amount of letters"))
        count_numbers = int(input("Give the amount of numbers"))
        count_symbols = int(input("Give the amount of symbols"))
        if count_alphabet + count_numbers + count_symbols < minimum:
            print("Too short password. Minimum length is:", minimum)
            sys.exit()
    else:
            count_alphabet, count_numbers, count_symbols = generate_random_numbers()
    password = password_generator(count_alphabet, count_numbers, count_symbols)

    while len(password) < minimum:
        #print("Too short generating again")
        count_alphabet, count_numbers, count_symbols = generate_random_numbers()
        password_list = password_generator(count_alphabet, count_numbers, count_symbols)
        password = ''.join(password_list)

    print("Generated password: ", password)

if __name__ == "__main__":
    main()