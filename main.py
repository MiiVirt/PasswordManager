import os, sys, csv
from cryptography.fernet import Fernet


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
            data_list.append({'Title': row['Title'], 'Username': row['Username'], 'Password': row['Password'].encode('utf-8'), 'Key': row['Key'].encode('utf-8')})
    return data_list


def main():
    print("Press '1' to save new credentials")
    print("Press '2' to see all currently saved credentials")
    print("Press '3' to edit an existing credential")
    response = input(": ")
    if response == '1':
        title = input("Type the title: ")
        username = input("Type the username: ")
        password = input("type the password:")
        key = generate_key()
        encrypted_data = encrypt_data(password, key)
        save_password(title, username, encrypted_data, key) #NOTE encrypted_data and key are saved as bytes here
    elif response == '2':
        data_list = read_passwords()
        passwords = []
        keys = []
        for data_set in data_list:
            passwords.append(data_set['Password'])
            keys.append(data_set['Key'])
        decrypted_passwords = [decrypt_data(password, key) for password, key in zip(passwords, keys)]
        for decrypted_data in decrypted_passwords:
            print(decrypted_data)

    elif response == '3':
        return


if __name__ == "__main__":
    main()
