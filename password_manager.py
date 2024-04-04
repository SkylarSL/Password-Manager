import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Get the hash or initialize one if it doesn't exist
def get_hash():

    # Check if hash exists
    try:
        hash_file = open("hash.txt", "r")
        hash = hash_file.readline()
        hash_file.close()
    except:

        # Get master password
        master_password = input("A master password does not seem to exist. Create a password: ")
        master_password = master_password.encode("ASCII")

        # Create a hash of the master password
        master_password_hash = hashes.Hash(hashes.SHA3_256())
        master_password_hash.update(master_password)
        hash = master_password_hash.finalize()

        # Write the hash to a file
        hash_file = open("hash.txt", "w")
        hash_file.write(str(hash))
        hash_file.close()

        print("Master key successfully created!")
    
    return hash


# Get the salt or initialize one if it is not made yet
def get_salt():

    try:
        salt_file = open("salt.txt", "r")
        salt = salt_file.readline().encode("ASCII")
        salt_file.close()
    except:
        salt_file = open("salt.txt", "w")
        salt = os.urandom(16)
        salt_file.write(str(salt))
        salt_file.close()

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


def main():

    hash = get_hash()

    # Check if given password is valid
    master_password = input("What is the master password? ").encode("ASCII")
    auth = check_master_password(master_password, hash)
    if auth:
        print("Success!")
    else:
        print("That password is incorrect.")
        exit()
    
    # Code for key stuff

    salt = get_salt()

    master_key = derive_key(master_password, salt)

    f = Fernet(master_key)

    token = f.encrypt(b"Secret message!")

    print(token)

    d_token = f.decrypt(token)

    print(d_token)

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