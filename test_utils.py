import utils
import pytest
import os


def test_getKey():
    # Check that it doesnt accept anything but SALT_LENGTH
    for i in (list(range(utils.SALT_LENGTH)) +
              list(range(utils.SALT_LENGTH + 1, 50))):
        with pytest.raises(AssertionError):
            utils.getKey("password", b"\x00" * i)
    # Check that it accepts SALT_LENGTH
    utils.getKey("password", b"\x00" * utils.SALT_LENGTH)
    # Check that it accepts different salt
    utils.getKey("password", (b"\x01\x02\x03\x04" + b"\x01" *
                              (utils.SALT_LENGTH - 4)))


def test_setupCipher():
    # Check that this standard call doesn't raise errors
    key = utils.getKey("password", b"\x00" * utils.SALT_LENGTH)
    iv = "\x00" * utils.IV_LENGTH
    utils.setupCipher(key, iv)


def test_setupMAC():
    # Check this standard call doesn't raise errors
    key = utils.getKey("password", b"\x00" * utils.SALT_LENGTH)
    content = b"Hi"
    utils.setupMAC(key, content)


def test_encryptToFile_writesFile():
    name = "test.txt"
    utils.encryptToFile(name, "this is a test", "password")
    assert os.path.isfile(name)


def test_encrypt_decrypt():
    fname = "test.txt"
    content = "this is a test"
    password = "password"
    utils.encryptToFile(fname, content, password)
    assert utils.decryptFromFile(fname, password) == content
