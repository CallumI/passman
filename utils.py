from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from sys import version_info as pythonVersion


assert pythonVersion >= (3,)

SALT_LENGTH = 8   # Recommmended 8 bytes
KEY_LENGTH = 32   # Must be 32 bytes for AES-256
IV_LENGTH = 16    # Must be 16 bytes for CBC
MAC_LENGTH = 32   # Using SHA256


def getKey(password, salt):
    """Returns a key derived from the password and a salt."""
    assert len(salt) == SALT_LENGTH
    return PBKDF2(password, salt, dkLen=KEY_LENGTH, count=1000, prf=None)


def setupCipher(key, iv):
    """Returns a setup cipher object. Ready for use with c.encrypt() or
    c.decrypt()."""
    assert len(iv) == IV_LENGTH
    assert len(key) == KEY_LENGTH
    return AES.new(key, AES.MODE_CFB, iv)


def setupMAC(key, content):
    """Returns a setup HMAC object, ready for h.digest() or h.verify(mac)."""
    return HMAC.new(key, msg=content, digestmod=SHA256)


def encryptToFile(fileName, plaintext, password):
    """Encrypts some plaintext with a key derived from a given password and
    writes it to a file in the standard format.

    Format:
        mac + salt_aes + salt_mac + iv + ciphertext

        Variable   | length          | Description
        ---------- | --------------- | ----------------------------------------
        mac        | HASH_LENGTH     | message authentication code
        salt_aes   | SALT_LENGTH     | random salt used to derive AES key
        salt_mac   | SALT_LENGTH     | random salt used to derive MAC key
        iv         | IV_LENGTH       | Initialisation vector for AES
        ciphertext | ~len(plaintext) | Encrypted plaintext with AES
    """
    # Initialise the random values
    salt_aes = Random.get_random_bytes(SALT_LENGTH)
    salt_mac = Random.get_random_bytes(SALT_LENGTH)
    iv = Random.get_random_bytes(IV_LENGTH)

    # Setup the cipher with a derived key and a random iv.
    cipher = setupCipher(getKey(password, salt_aes), iv)
    # Encrypt the plaintext and create the fileContent.
    ciphertext = cipher.encrypt(plaintext)
    fileContent = salt_aes + salt_mac + iv + ciphertext

    # Get a MAC (message authentication code) from the fileContent and
    # different derived key.
    h = setupMAC(getKey(password, salt_mac), fileContent)
    mac = h.digest()
    assert len(mac) == MAC_LENGTH

    # Write to the file
    with open(fileName, "wb") as fHandle:
        fHandle.write(mac)
        fHandle.write(fileContent)


def decryptFromFile(fileName, password):
    """Reads the headers and ciphertext from the file. Decrypts the ciphertext
    and verifies the MAC. Returns the plaintext."""
    with open(fileName, "rb") as fHandle:
        mac = fHandle.read(MAC_LENGTH)
        salt_aes = fHandle.read(SALT_LENGTH)
        salt_mac = fHandle.read(SALT_LENGTH)
        iv = fHandle.read(IV_LENGTH)
        ciphertext = fHandle.read()
    # Get the content and verify MAC against it
    fileContent = salt_aes + salt_mac + iv + ciphertext
    h = setupMAC(getKey(password, salt_mac), fileContent)
    h.verify(mac)  # Should raise value error if not valid

    cipher = setupCipher(getKey(password, salt_aes), iv)
    return cipher.decrypt(ciphertext)
