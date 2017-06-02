import utils
import pytest
import os


def test_setupCipher():
    # Check that this standard call doesn't raise errors
    iv = b"\x00" * utils.IV_LENGTH
    utils.setupCipher("password", b"\x00" * utils.SALT_LENGTH, iv)


def test_encryptToFile_writesFile():
    # Tests encryptToFile() actually makes a file.
    name = "test.enc"
    utils.encryptToFile(name, "this is a test", "password")
    assert os.path.isfile(name)


def test_encrypt_decrypt():
    # Tests encrypt(decrypt(plaintext)) == plaintext
    fname = "test.enc"
    content = "this is a test"
    password = "password"
    utils.encryptToFile(fname, content, password)
    assert utils.decryptFromFile(fname, password).decode() == content


def test_mac():
    # Tests the cipher text can't be modified without alerting the MA
    fname = "test.enc"
    content = "this is a test"
    password = "password"
    utils.encryptToFile(fname, content, password)
    with open(fname, "ab") as fhandle:
        fhandle.write(b"additional stuff")
    with pytest.raises(ValueError):
        utils.decryptFromFile(fname, password)
