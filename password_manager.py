import base64
import os
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Initialize the files
def initialize():

    print("Since this is your first time using Vult we will start by initializing files...")

    # Initialize the salt file
    salt_file = open("salt.txt", "w")
    salt = os.urandom(16)
    salt_file.write(str(salt))
    salt_file.close()
    #os.chmod("salt.txt", 0o644)
    print("Salt file created!")

    # Initialize accounts file
    tmp = open("accounts.txt.", "x")
    tmp.close()
    #os.chmod("accounts.txt", 0o644)
    print("Accounts file created!")

    # Initialize the hash file
    # Get master password
    master_password = input("Create a master password: ")
    master_password = master_password.encode("ASCII")

    # Create a hash of the master password
    master_password_hash = hashes.Hash(hashes.SHA3_256())
    master_password_hash.update(master_password)
    del master_password
    hash = master_password_hash.finalize()

    # Write the hash to the hash file
    hash_file = open("hash.txt", "w")
    hash_file.write(str(hash))
    del hash
    hash_file.close()
    #os.chmod("hash.txt", 0o644)
    print("Master key successfully created!")
    print("Please login now...")

# Get the hash
def get_hash():

    # Check if hash exists
    try:
        hash_file = open("hash.txt", "r")
        hash = hash_file.readline()
        hash_file.close()
    except:
        print("Failed")
    
    return hash


# Get the salt
def get_salt():

    try:
        salt_file = open("salt.txt", "r")
        salt = salt_file.readline().encode("ASCII")
        salt_file.close()
    except:
        print("Failed")

    return salt

# Checks the given password against known master password
def check_master_password(imposter, hash):

    # Create hash of imposter
    imposter_hash = hashes.Hash(hashes.SHA3_256())
    imposter_hash.update(imposter)
    imposter_hash = str(imposter_hash.finalize())

    if imposter_hash == hash:
        return True
    else:
        return False

# Derive a key using the master password
def derive_key(master_password, salt):

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )

    kdf_key = kdf.derive(master_password)
    key = base64.urlsafe_b64encode(kdf_key)

    return key


def get_account(master_password):
    print("Here is a list of your current accounts:\n")
    accounts = open("accounts.txt", "r")
    accounts_list = accounts.readlines()
    accounts.close()
    account_pairs = {}
    for account in accounts_list:
        pair = account.split(" ")
        name = pair[0]
        print(name)
        token = (pair[1])[:-1]
        account_pairs[name] = token

    chosen_account = input("\nWhat account would you like to access? ")

    # Initialize decryption
    try:
        salt = get_salt()
        key = derive_key(master_password, salt)
        fernet = Fernet(key)
        del key
    except:
        print("Failed")
        return 0

    account_pass = fernet.decrypt(account_pairs[chosen_account].encode("ASCII"))
    print("Here is the password for {}: {}".format(chosen_account, account_pass.decode("ASCII")))

    return 1


def add_account(master_password):
    account_name = input("What account would you like to add? ")
    account_pass = input("What password would you like to use for this account? ").encode("ASCII")

    # Initialize encryption
    try:
        salt = get_salt()
        key = derive_key(master_password, salt)
        fernet = Fernet(key)
        del key
    except:
        print("Failed")
        return 0

    try:
        accounts = open("accounts.txt", "a")
        token = fernet.encrypt(account_pass)
        accounts.write("{} {}\n".format(account_name, token.decode("ASCII")))
        accounts.close()
        del token
        print("Successfully added account!")
    except:
        print("Failed")
        return 0

    return 1


def del_account():
    print("Here is a list of your current accounts:\n")
    accounts = open("accounts.txt", "r")
    accounts_list = accounts.readlines()
    accounts.close()
    account_pairs = {}
    for account in accounts_list:
        pair = account.split(" ")
        name = pair[0]
        print(name)
        token = (pair[1])[:-1]
        account_pairs[name] = token

    chosen_account = input("\nWhat account would you like to delete? ")
    account_pairs.pop(chosen_account)

    accounts = open("accounts.txt", "w")
    accounts_list = accounts.write("")
    accounts.close()
    accounts = open("accounts.txt", "a")
    for account, token in account_pairs.items():
        accounts.write("{} {}\n".format(account, token))
    accounts.close()
    del account_pairs

    print("Successfully deleted {} account!".format(chosen_account))

    return 0


def main():

    print("Welcome to Vult!")

    # Check if things need to be initialized
    try:
        tmp = open("hash.txt", "r")
        tmp.close()
        tmp = open("accounts.txt", "r")
        tmp.close()
        tmp = open("salt.txt", "r")
        tmp.close()
    except:
        initialize_check = input("You seem to be missing necessary files. Is this your first time using Vult? [yes/no] ")
        match initialize_check:
            case "yes":
                initialize()
            case "no":
                # Debug here
                print("I don't know what to do yet :(")
                exit()

    # Code to turn Vult into an argument based commandline
    '''
    manual = " Vult <masterpassword> -<command> <account> <accountpassword> ...\
        <masterpassword>, the password used to authenticate Vult usage \
        -<command>, actions for accounts \
            -g/get, get a password for an account (requires account name) \
            -a/add, add an account (requires account name and corresponding password) \
            -d/del, delete an account (requires account name) \
        <account>, specify an account you want to perform an action on \
        <accountpassword>, specify the password for the corresponding account \
    "

    if len(sys.argv) != 3:
        exit()
    master_password = str(sys.argv[1])
    for i in range(2, len(sys.argv)):
        command = sys.argv[i]
        if command == "-g" or command == "-get":
            try:
                account = sys.argv[i+1]
            except:
                print("No account specified to get.")
                exit()
            get_account()
        elif command == "a" or command == "-add":
            try:
                account = sys.argv[i+1]
            except:
                print("No account specified to add.")
                exit()
            add_account()
        elif command == "d" or command == "-del":
            try:
                account = sys.argv[i+1]
            except:
                print("No account specified to delete.")
                exit()
            del_account()
    '''

    # Get the hash
    hash = get_hash()

    # Check if given password is valid
    master_password = input("What is your master password? ").encode("ASCII")
    auth = check_master_password(master_password, hash)
    if auth:
        print("Success!")
    else:
        print("That password is incorrect.")
        exit()

    action = input("What would you like to do?\n \
          [r] get the password for an account\n \
          [w] add an account and password\n \
          [d] delete an account and password\n")
    
    match action:
        case "r":
            get_account(master_password)
        case "w":
            add_account(master_password)
        case "d":
            del_account()
        case _:
            print("Action does not exist or no action was given")

    # Verify key, needed...?
    '''
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        kdf.verify(b"test", kdf_key)
    except:
        print("invalid password")
'''

main()