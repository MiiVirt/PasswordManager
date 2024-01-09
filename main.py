import os, sys, csv
from cryptography.hazmat.backends import  default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_data(data):
    cipher = Cipher(algorithms.AES(), modes.CFB(), backend=default_backend())
    encryptor = cipher.encryptor()
    data = data.encode('utf-8')
    encrypted_password = encryptor.update(data) + encryptor.finalize()
    return encrypted_password
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


if __name__ == "__main__":
    main()
