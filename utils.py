from Cryptodome.Cipher import AES
from Cryptodome import Random
from Cryptodome.Protocol.KDF import PBKDF2
from sys import version_info as pythonVersion


assert pythonVersion >= (3,)

SALT_LENGTH = 8   # Recommmended 8 bytes
KEY_LENGTH = 32   # Must be 32 bytes for AES-256
IV_LENGTH = 12    # Must be 16 bytes for CBC
MAC_LENGTH = 16


def setupCipher(password, salt, iv):
    """Returns a setup cipher object. Ready for use with c.encrypt() or
    c.decrypt()."""
    assert len(iv) == IV_LENGTH
    assert len(salt) == SALT_LENGTH
    key = PBKDF2(password, salt, dkLen=KEY_LENGTH, count=1000, prf=None)
    return AES.new(key, AES.MODE_CCM, iv)


def encryptToFile(fileName, plaintext, password):
    """Encrypts some plaintext string with a key derived from a given password
    and writes it to a file in the standard format.

    Format:
        mac + salt + iv + ciphertext

        Variable   | length          | Description
        ---------- | --------------- | ----------------------------------------
        mac        | HASH_LENGTH     | message authentication code
        salt       | SALT_LENGTH     | random salt used to derive AES key
        iv         | IV_LENGTH       | Initialisation vector for AES
        ciphertext | ~len(plaintext) | Encrypted plaintext with AES
    """
    # Initialise the random values
    salt = Random.get_random_bytes(SALT_LENGTH)
    iv = Random.get_random_bytes(IV_LENGTH)

    # Setup the cipher with a derived key and a random iv.
    cipher = setupCipher(password, salt, iv)
    # Encrypt the plaintext and generate the mac
    ciphertext = cipher.encrypt(plaintext.encode())
    mac = cipher.digest()
    assert len(mac) == MAC_LENGTH

    # Write to the file
    with open(fileName, "wb") as fHandle:
        fHandle.write(mac)
        fHandle.write(salt)
        fHandle.write(iv)
        fHandle.write(ciphertext)


def decryptFromFile(fileName, password):
    """Reads the headers and ciphertext from the file. Decrypts the ciphertext
    and verifies the MAC. Returns the plaintext."""
    with open(fileName, "rb") as fHandle:
        mac = fHandle.read(MAC_LENGTH)
        salt = fHandle.read(SALT_LENGTH)
        iv = fHandle.read(IV_LENGTH)
        ciphertext = fHandle.read()
    cipher = setupCipher(password, salt, iv)
    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(mac)
    return plaintext
