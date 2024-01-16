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
        save_password(title, username, encrypted_data, key)
    elif response == '2':
        data_list = read_passwords()
        for data_set in data_list:
            decrypted_password = decrypt_data(data_set['Password'], data_set['Key'])
            print(f"Title: {data_set['Title']}, Username: {data_set['Username']}, Password: {decrypted_password.decode('utf-8')}")
    elif response == '3':
        update_title = input("What password would you like to edit? ")
        new_password = input("Enter the new password: ")
        edit_passwords(update_title, new_password)

        return


if __name__ == "__main__":
    main()
