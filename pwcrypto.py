import base64
import secrets
import cryptography.exceptions
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#Constants
KDF_ALGORITHM = hashes.SHA256()
KDF_LENGTH = 32
KDF_ITERATIONS = 120000

#Salts and Encrypts a string with a password. Returns ciphertext and salt
def encrypt(plaintext: str, password: str) -> (bytes, bytes):
    #Derive a symmetric key using the password and a fresh random salt
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt, iterations=KDF_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))

    #Encrypt the message
    f = Fernet(base64.urlsafe_b64encode(key))
    ciphertext = f.encrypt(plaintext.encode("utf-8"))

    return ciphertext, salt

#Decrypts some ciphertext using the password and salt. Returns plaintext
def decrypt(ciphertext: bytes, password: str, salt: bytes) -> str:
    #Derive the symmetric key using the password and provided salt
    kdf = PBKDF2HMAC(algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt, iterations=KDF_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))

    #Decrypt the message
    f = Fernet(base64.urlsafe_b64encode(key))
    try:
        plaintext = f.decrypt(ciphertext)
        return plaintext.decode("utf-8")
    except cryptography.fernet.InvalidToken as _:
        print(f"InvalidToken")
    except Exception as e:
        print(f"Unexpected error: {e}")