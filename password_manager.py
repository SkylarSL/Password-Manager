import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def check_master_password(imposter):

    # Create digest of imposter
    imposter_hash = hashes.Hash(hashes.SHA3_256())
    imposter_hash.update(imposter)
    imposter_digest = str(imposter_hash.finalize())

    # Get known master password hash
    master_password_file = open("master_password.txt", "r")
    master_password_digest = master_password_file.readline()
    master_password_file.close()

    if imposter_digest == master_password_digest:
        return True
    else:
        return False


master_password_file = open("master_password.txt", "r")
check_empty = master_password_file.readline()
master_password_file.close()

if check_empty == None or check_empty == "":

    # Get master password
    master_password = input("Create a password:")
    master_password = master_password.encode("ASCII")

    # Create a hash of the master password
    master_password_hash = hashes.Hash(hashes.SHA3_256())
    master_password_hash.update(master_password)
    master_password_digest = master_password_hash.finalize()

    # Write the master password hash to a file
    master_password_file = open("master_password.txt", "w")
    master_password_file.write(str(master_password_digest))
    master_password_file.close()
    
else:

    # Check if returning password is valid
    imposter = input("What is the password? ")
    auth = check_master_password(imposter.encode("ASCII"))



# Code for key stuff
'''
salt = os.urandom(16)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)

kdf_key = kdf.derive(master_password)

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


key = base64.urlsafe_b64encode(kdf_key)

f = Fernet(key)

token = f.encrypt(b"Secret message!")

print(token)

d_token = f.decrypt(token)

print(d_token)
'''