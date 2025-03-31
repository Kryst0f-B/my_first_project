# cracking algorithm

import hashlib
from passlib.hash import nthash


"""This scripts takes input from
the HashCracking Window and tries
to match user entered hash to hash
of possible password from the list"""

#digests the password into hash using passlib and hashlib libraries
def encoder(password, algorithm):
    if algorithm == "sha_256":
        digest = hashlib.sha256(password.encode()).hexdigest()
        return digest
    elif algorithm == "md5":
        digest = hashlib.md5(password.encode()).hexdigest()
        return digest
    elif algorithm == "sha1":
        digest = hashlib.sha1(password.encode()).hexdigest()
        return digest
    elif algorithm == "ntlm":
        digest = nthash.hash(password)
        return digest

#takes user input from the HashCracking class and tries to match it to password hash
#the HashCracking class also sets hash algorithm which is used
def main(cleaned_hash, algorithm):
    try:
        with open("passwords.txt") as file:
            for line in file:
                password = line.strip()
                hash_code = encoder(password, algorithm)

                if hash_code == cleaned_hash:
                    return f"Password is: {password}"

            return "Password not found"

    except FileNotFoundError:
        return "File not found error:\nPassword was not found"