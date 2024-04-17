import base64
import os
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
    print("Salt file created!")

    # Initialize accounts file
    tmp = open("accounts.txt.", "x")
    tmp.close()
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
    print("Master key successfully created!")
    print("Please login now...")

# Get the hash or initialize one if it doesn't exist
def get_hash():

    # Check if hash exists
    try:
        hash_file = open("hash.txt", "r")
        hash = hash_file.readline()
        hash_file.close()
    except:
        print("Failed")
    
    return hash


# Get the salt or initialize one if it is not made yet
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
    account_pairs = {}
    for account in accounts_list:
        pair = account.split(" ")
        name = pair[0]
        print(name)
        token = (pair[1])[:-1]
        print(token)
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

    action = input("What would you like to do?\n\
          [r] get the password for an account\n\
          [w] add an account and password\n\
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

    # encrypt/decrypt
    '''

    token = fernet.encrypt(b"Secret message!")

    print(token)

    d_token = fernet.decrypt(token)

    print(d_token)

    '''

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