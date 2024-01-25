import csv, sys, ast, base64
from Password_Generator import generator
from Encoder import encoder
from cryptography.fernet import Fernet

#TODO add master password system with PassCrypt
#TODO separate credentials and key to different save locations for security
#TODO Commandline implementation with getpass to hide passwords
#TODO GUI
#TODO 2FA
#TODO SQL Database
#TODO Error handling, upper/lower key handling
#TODO Credential categories and search
#TODO Autofill
#TODO File encryption

def generate_key(): #Generate key for encryption
    return Fernet.generate_key()


def encrypt_data(data, key):
    cipher_suite = Fernet(key) #Creates cipher with the key
    data_bytes = data.encode('utf-8') #Transforms data into bytes
    encrypted_password = cipher_suite.encrypt(data_bytes) #Encrypts the data
    return encrypted_password


def decrypt_data(data, key):
    cipher_suite = Fernet(key) #Creates cipher with the key
    decrypted_password = cipher_suite.decrypt(data) #Decrypts the data
    return decrypted_password


def save_password(title, username, password, key):
    file_path = "passwords.csv"
    with open(file_path, 'a', newline='') as csvfile:
        fieldnames = ['Title', 'Username', 'Password', 'Key']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if csvfile.tell() == 0:
            writer.writeheader()
        writer.writerow({'Title': title, 'Username': username, 'Password': password.decode('utf-8'), 'Key': key.decode('utf-8')})
    print("Password saved")


def read_passwords():
    file_path = "passwords.csv"
    data_list = []
    with open(file_path, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            data_list.append({
                'Title': row['Title'],
                'Username': row['Username'],
                'Password': row['Password'],
                'Key': row['Key']
            })
    return data_list

def edit_passwords(title, new_password):
    file_path = "passwords.csv"
    data_list = read_passwords()

    for data_set in data_list:
        if data_set['Title'] == title:
            key = data_set['Key']
            encrypted_password = encrypt_data(new_password, key)
            data_set['Password'] = encrypted_password.decode('utf-8')

        with open(file_path, 'w', newline='') as csvfile:
            fieldnames = ['Title', 'Username', 'Password', 'Key']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for data_set in data_list:
                writer.writerow(data_set)


def edit_username(title, new_username):
    file_path = "passwords.csv"
    data_list = read_passwords()

    for data_set in data_list:
        if data_set['Title'] == title:
            data_set['Username'] = new_username
            with open(file_path, 'w', newline='') as csvfile:
                fieldnames = ['Title', 'Username', 'Password', 'Key']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for data_set in data_list:
                    writer.writerow(data_set)


def delete_password(title):
    file_path = "passwords.csv"
    data_list = read_passwords()

    updated_data = [data_set for data_set in data_list if data_set['Title'] != title] #Filter out the entry with the specified title

    with open(file_path, 'w', newline='') as csvfile: #Write the modified data back to the file
        fieldnames = ['Title', 'Username', 'Password', 'Key']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if csvfile.tell() == 0: #Write header only if the file is not empty
            writer.writeheader()

        writer.writerows(updated_data)

def check_password_strength(password):
    error = 0 #Counter for problems with password

    if len(password) < 8: #Check the lenght
        print("Password needs to be at least 8 characters!")
        error += 1
    if any(char.isdigit() for char in password) == False: #Check if there is at least one number in password
        print("There needs to be at least one numeral in the password!")
        error += 1
    if any(not char.isalnum() and not char.isspace() for char in password) == False: #Check that there's at least one symbol in password
        print("There needs to be at least one symbol in the password!")
        error += 1
    if any(char.isupper() for char in password) == False: #Check if there's a uppercase letter in password
        print("There needs to be at least one uppercase letter in password!")
        error += 1
    if any(char.islower() for char in password) == False: #Check if there's a lowercase letter in password
        print("There needs to be at least one lowercase letter in password!")
        error += 1
    if error > 0: #If there has been at least one problem with the password, program closes.
        sys.exit()


def save_credentials(username, password, salt):
    file_path = "credentials.csv"
    credentials = read_credentials()

    # Base64 encode the salt
    salt_str = base64.b64encode(salt).decode('utf-8')

    hashed_password = encoder.hash_data(password, salt)

    with open(file_path, 'a', newline='') as csvfile:
        fieldnames = ['username', 'password', 'salt']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if csvfile.tell() == 0:
            writer.writeheader()
        writer.writerow({'username': username, 'password': hashed_password, 'salt': salt_str})

    print("Credentials saved!")


def read_credentials():
    file_path = "credentials.csv"
    credentials = []
    with open(file_path, "r", newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            salt = base64.b64decode(row['salt'])
            credentials.append({'username': row['username'], 'password': row['password'], 'salt': salt})
    return credentials


def authenticate_user(users, username, entered_password, salt):
    user_exists = any(user['username'] == username for user in users)
    if user_exists:
        user_data = next(user for user in users if user['username'] == username)
        print(entered_password)
        print(salt)
        input_password_hashed = encoder.hash_data(entered_password, salt)
        stored_password_hashed = user_data['password']
        print(stored_password_hashed)
        print(input_password_hashed)
        if stored_password_hashed == input_password_hashed:
            return True
        return False
    else:
        return False


def login():
    #users = read_credentials()
    while True:
        print("Press '1' to login")
        print("Press '2' to create a new user")
        print("Press '3' to exit")
        response = input(": ")
        if response == '1':
            username = input("Username: ")
            password = input("Password: ")
            credentials = read_credentials()
            user_exists = any(user['username'] == username for user in credentials)
            if user_exists:
                user_data = next(user for user in credentials if user['username'] == username)
                salt = user_data['salt']
                stored_password = user_data['password']
                if authenticate_user(credentials, username, password, salt):
                    print(f"Welcome, {username}!")
                    break
                else:
                    print("Login failed. Invalid password.")
            else:
                print("Login failed. Invalid username.")
        elif response == '2':
            username = input("Username: ")
            password = input("Password: ")
            salt = encoder.generate_random_16byte()
            save_credentials(username, password, salt)
            print("User created successfully!")
        elif response == '3':
            sys.exit()
        else:
            print("Invalid option. Please choose a valid option.")

def main():
    login()
    print("Press '1' to save new credentials")
    print("Press '2' to see all currently saved credentials")
    print("Press '3' to edit an existing credential")
    print("Press '4' to delete existing credentials")
    response1 = input(": ")
    if response1 == '1':
        title = input("Type the title: ")
        username = input("Type the username: ")
        response2 = input("Would you like to automatically generated password? (y/n)").lower()
        if response2 == 'n':
            password = input("type the password: ")
        elif response2 == 'y':
            count_alphabet, count_numbers, count_symbols = generator.generate_random_numbers()
            password = generator.password_generator(count_alphabet, count_numbers, count_symbols)
        check_password_strength(password)
        key = generate_key()
        encrypted_data = encrypt_data(password, key)
        save_password(title, username, encrypted_data, key)
    elif response1 == '2':
        data_list = read_passwords()
        for data_set in data_list:
            decrypted_password = decrypt_data(data_set['Password'], data_set['Key'])
            print(f"Title: {data_set['Title']}, Username: {data_set['Username']}, Password: {decrypted_password.decode('utf-8')}")
    elif response1 == '3':
        response2 = input("Press '1' to edit username and password, '2' to edit username or '3' to edit password: ")
        if response2 == '1':
            update_title = input("What credential would you like to edit? ")
            new_username = input("Enter the new username: ")
            new_password = input("Enter the new password: ")
            check_password_strength(new_password)
            edit_username(update_title, new_username)
            edit_passwords(update_title, new_password)
        elif response2 == '2':
            update_title = input("What credential would you like to edit? ")
            new_username = input("Enter the new username: ")
            edit_username(update_title, new_username)
        elif response2 == '3':
            update_title = input("What credential would you like to edit? ")
            new_password = input("Enter the new password: ")
            check_password_strength(new_password)
            edit_passwords(update_title, new_password)
    elif response1 == '4':
        title = input("What credentials would you like to delete? ")
        delete_password(title)


if __name__ == "__main__":
    main()