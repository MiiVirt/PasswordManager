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
    cipher_suite = Fernet(key) #creates cipher with the given key
    decrypted_password = cipher_suite.decrypt(data).decode('utf-8') #decrypts and decodes the data
    return decrypted_password


def save_password(title, username, password, key):
    file_path = "passwords.csv"
    with open(file_path, 'a', newline='') as csvfile:
        fieldnames = ['Title', 'Username', 'Password', 'Key']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if csvfile.tell() == 0:
            writer.writeheader()
        writer.writerow({'Title': title, 'Username': username, 'Password': password, 'Key': key.decode('utf-8')})
    print("Password saved")


def update_info():
    file_path = "passwords.csv"


def read_passwords():
    file_path = "passwords.csv"
    data_list = []
    with open(file_path, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            data_list.append({'Title': row['Title'], 'Username': row['Username'], 'Password': row['Password'], 'Key': row['Key']})
    return data_list



def main():
    title = input("Type the title: ")
    username = input("Type the username: ")
    password = input("type the password:")
    key = generate_key()

    encrypted_data = encrypt_data(password, key)
    #print(encrypted_data)
    save_password(title, username, encrypted_data, key)

    data_list = read_passwords()
    for data_set in data_list:
        print(f"Title: {data_set['Title']}, Username: {data_set['Username']}, Password: {data_set['Password']}, Key: {data_set['Key']}")


    decrypted_data = decrypt_data(encrypted_data, key)
    print(decrypted_data)

if __name__ == "__main__":
    main()
