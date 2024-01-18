import csv
from cryptography.fernet import Fernet

#TODO add Password generator
#TODO add master password system with PassCrypt
#TODO separate credentials and key to different save locations for security
#TODO Commandline implementation with getpass to hide passwords
#TODO Password strenght checker
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
    cipher_suite = Fernet(key) #creates cipher with the key
    data_bytes = data.encode('utf-8') #transforms data into bytes
    encrypted_password = cipher_suite.encrypt(data_bytes) #encrypts the data
    return encrypted_password


def decrypt_data(data, key):
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(data)
    decrypted_password = decrypted_data
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

    # Filter out the entry with the specified title
    updated_data = [data_set for data_set in data_list if data_set['Title'] != title]

    # Write the modified data back to the file
    with open(file_path, 'w', newline='') as csvfile:
        fieldnames = ['Title', 'Username', 'Password', 'Key']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write header only if the file is not empty
        if csvfile.tell() == 0:
            writer.writeheader()

        writer.writerows(updated_data)


def main():
    print("Press '1' to save new credentials")
    print("Press '2' to see all currently saved credentials")
    print("Press '3' to edit an existing credential")
    print("Press '4' to delete existing credentials")
    response = input(": ")
    if response == '1':
        title = input("Type the title: ")
        username = input("Type the username: ")
        password = input("type the password:")
        key = generate_key()
        encrypted_data = encrypt_data(password, key)
        save_password(title, username, encrypted_data, key)
    elif response == '2':
        data_list = read_passwords()
        for data_set in data_list:
            decrypted_password = decrypt_data(data_set['Password'], data_set['Key'])
            print(f"Title: {data_set['Title']}, Username: {data_set['Username']}, Password: {decrypted_password.decode('utf-8')}")
    elif response == '3':
        response2 = input("Press '1' to edit username and password, '2' to edit username or '3' to edit password: ")
        if response2 == '1':
            update_title = input("What credential would you like to edit? ")
            new_username = input("Enter the new username: ")
            new_password = input("Enter the new password: ")
            edit_username(update_title, new_username)
            edit_passwords(update_title, new_password)
        elif response2 == '2':
            update_title = input("What credential would you like to edit? ")
            new_username = input("Enter the new username: ")
            edit_username(update_title, new_username)
        elif response2 == '3':
            update_title = input("What credential would you like to edit? ")
            new_password = input("Enter the new password: ")
            edit_passwords(update_title, new_password)
    elif response == '4':
        title = input("What credentials would you like to delete? ")
        delete_password(title)


if __name__ == "__main__":
    main()