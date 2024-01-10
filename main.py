import os, sys, csv
from cryptography.fernet import Fernet


def encrypt_data(data):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    data_bytes = data.encode('utf-8')
    encrypted_password = cipher_suite.encrypt(data_bytes)
    return encrypted_password, key

def decrypt_data(data, key):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(data).decode('utf-8')
    return decrypted_password


def save_password(title, username, password):
    file_path = "passwords.txt"
    with open(file_path, 'a') as file:
        file.write(f"{title},{username},{password}\n")
    print("Password saved")


def read_passwords():
    file_path = "passwords.txt"
    data_list = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            title, username, password = line.strip().split(',')
            data_list.append({'Title': title, 'Username': username, 'Password': password})
    return data_list



def main():
    title = input("Type the title: ")
    username = input("Type the username: ")
    password = input("type the password:")
    save_password(title, username, password)
    data_list = read_passwords()
    for data_set in data_list:
        print(f"Title: {data_set['Title']}, Username: {data_set['Username']}, Password: {data_set['Password']}")
    data = input("Give data")
    encrypted_data, key = encrypt_data(data)
    print(encrypted_data)
    decrypted_data = decrypt_data(encrypted_data, key)
    print(decrypted_data)

if __name__ == "__main__":
    main()
