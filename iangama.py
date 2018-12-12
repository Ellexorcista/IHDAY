#! python3

"""
@auhtor: Leonel Jose Pena Gamboa
This program saves the user passwords for different account and copies it
into the clipboard so it can be pasted.
"""

import sys
import os

# First I had to import system and os and do the following to set the path of the modules the program is using
# Otherwise, it didn't know where to find the libraries.
project_directory = os.path.dirname(os.path.abspath(__file__))
print('%s\\venv\\Lib\\site-packages' % project_directory)
sys.path.append('%s\\venv\\Lib\\site-packages' % project_directory)
sys.path.append('%s\\venv\Lib\\site-packages\\pyperclip' % project_directory)
import pyperclip
import termcolor
import csv
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PASSWORDS = {}
salt = b'\x00\n\xd6\x17\xd6\xbc8\x13&i~\xff\xe7@\x0bA'

"""
Read csv data with all passwords
"""


def read_data(mp, file="passwords.csv"):
    with open(project_directory + "\\" + file, "r") as f:
        csvreader = csv.reader(f)
        global PASSWORDS
        for item in csvreader:
            PASSWORDS[item[0].encode()] = item[1].encode()
        PASSWORDS = decrypt(mp)


def save_data(mp, file="passwords.csv", mp_file="mp.csv"):
    with open(project_directory + "\\" + mp_file, "r+") as f:
        f.write(hashlib.sha512(mp.encode("utf-8")).hexdigest())
    with open(project_directory + "\\" + file, "r+") as f:
        count = 0
        global PASSWORDS
        PASSWORDS = encrypt(mp)
        for item in PASSWORDS:
            count += 1
            if count < len(PASSWORDS):
                f.write(item.decode() + "," + PASSWORDS[item].decode() + "\n")
            else:
                f.write(
                    item.decode() + "," + PASSWORDS[item].decode())  # This case handles the last item, so when writing it into the csv
                # file it doesn't add the new line break at the end


"""
Encrypts the file using a password.
"""


def encrypt(password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))  # The last bit is the padding.
    f = Fernet(key)
    encrypted_passwords = {}
    for item in PASSWORDS:
        k = f.encrypt(item.encode())
        v = f.encrypt(PASSWORDS[item].encode())
        encrypted_passwords[k] = v
    return encrypted_passwords


"""
Decrypts the file using a password
"""


def decrypt(password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    derived_kdf = kdf.derive(password.encode())
    if len(derived_kdf) % 4 == 1:
        print("fatal error")
        exit()
    key = base64.urlsafe_b64encode(derived_kdf) + (b"=" * (len(derived_kdf) % 4))  # The last bit is the padding
    f = Fernet(key)
    decrypted_passwords = {}
    for item in PASSWORDS:
        k = f.decrypt(item)
        v = f.decrypt(PASSWORDS[item])
        decrypted_passwords[k.decode()] = v.decode()
    return decrypted_passwords


"""
Copies the password into the clipboard to be pasted
"""


def retrieve_pass(id_account):
    try:
        pyperclip.copy(PASSWORDS[id_account])
        print("The password has been copied to the clipboard. You can paste it now.")
    except KeyError:
        print(termcolor.colored("The id doesn't exist", "red"))


"""
Adds and new entry with an id which refer to the account and the password related to it (use input focused) 
"""


def add_pass():
    id_account = input("Enter an id which will refer to the passwords of said account: ")
    password = input("Now insert the password to be related to the previous id: ")
    if id_account in PASSWORDS:
        while True:
            choice = input("The id already exists in the database. Do you want to overwrite (Y/N): ")
            if choice.lower() == "n":
                print("Ok. I won't :v")
                break
            elif choice == "y":
                PASSWORDS[id_account] = password
                print("Password overwritten")
                break
            else:
                print(termcolor.colored("The input is invalid! Please, enter 'Y' for 'yes' or 'N' for 'no': ", "red"))
    else:
        PASSWORDS[id_account] = password
        print("Password saved")


"""
It deletes an entry of the dictionary where the passwords are stored (user input focused).
"""


def del_pass():
    id_account = input("Enter the id of the account for which the password will be deleted: ")
    if id_account in PASSWORDS:
        old_password = PASSWORDS.pop(id_account)
        print("The item with id:", id_account, "and password:", old_password, "has been deleted")
    else:
        print(termcolor.colored("Error 666: The account you specified does not exist", "red"))


"""
Shows the available account to retrieve passwords from
"""


def show_accounts():
    if len(PASSWORDS) != 0:
        print("Stored account's passwords:")
        for k in PASSWORDS.keys():
            print("-", k)
    else:
        print("There are not accounts stored yet! :(")


"""
It prints a list of available commands and their use
"""


def help_me():
    print("The following command are available which can also be accessed using the first letter of the command: ")
    print("'add' ('a'): Adds a new account and password. If thee account already exits, you can choose to overwrite")
    print("'del' ('d'): Deletes an account")
    print("'show' ('s'): Shows the existent accounts")
    print("'retrieve' ('r'): Retrieves the password associated to the id and copies it to the clipboard")
    print("'masterpass' ('mp'): Sets the master password for a new one.")
    print("'quit' ('q'): Quits the program")


"""
Main function of the program
"""


def main():
    user_pass = ""
    with open(project_directory + "\\" + "mp.csv", "r") as f:
        hash_password = (f.readline())
    while hashlib.sha512(user_pass.encode("utf-8")).hexdigest() != hash_password:
        user_pass = input("Enter password: ")

        if hashlib.sha512(user_pass.encode("utf-8")).hexdigest() != hash_password:
            print("Incorrect password. Try again.")

    print("Welcome to IANGAMA Password Manager (I Am Not Good At Making Acronyms)")
    print("If you need help to remember the command enter 'h' for help ;D")
    read_data(user_pass)
    sign = "~>"
    while True:
        command = input(sign).lower()
        if command == "add" or command == "a":  # This should be a switch using switcher, but it works with if
            add_pass()  # so...whatever.
        elif command == "del" or command == "d":
            del_pass()
        elif command == "show" or command == "s":
            show_accounts()
        elif command == "help" or command == "h":
            help_me()
        elif command == "retrieve" or command == "r":
            retrieve_pass(input("Enter id of the account: "))
        elif command == "masterpass" or command == "mp":
            user_pass = input("Enter new master password:")
        elif command == "quit" or command == "q":
            print("Thank you for using IANGAMA! :D Bye")
            save_data(user_pass)
            break
        else:
            print("What you wrote doesn't match any command. Try again please, and sorry",
                  termcolor.colored("<3", "red"))


if __name__ == "__main__":
    main()
