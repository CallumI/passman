#! /usr/bin/env python3
"""Very simple password storing application.

Usage:
    python3 cli.py
    password: <enter password>
    <cmd>
    <response>
"""

import getpass
import utils
import json
from os.path import isfile, dirname, realpath, join
from shutil import copyfile
import time
import pyperclip

STORED_FILE_NAME = "store"
SCRIPT_DIRECTORY = dirname(realpath(__file__))
STORED_FILE_PATH = join(SCRIPT_DIRECTORY, "{}.enc".format(STORED_FILE_NAME))


COMMANDS = {
    "list": "List the titles of all saved entries.",
    "help": "Display a list of commands.",
    "show <title>": "Shows values of title.",
    "set <title>": "Prompt for setting values of title.",
    "undo": "Reset any changes made this log in.",
    "exit": "Quit the program.",
    "remove <title>": "Remove a given title.",
    "copy <title> [<attribute>]": "Copy (default: Password) to clipboard."
}
MAX_COMMAND_LENGTH = max(len(key) for key in COMMANDS)


ATTRIBUTES = {
    "Title": "the (unique) title of this entry",
    "Password": "the saved password",
    "Email": "the associated email address",
    "Notes": "any notes for this entry",
    "Username": "the username for this entry"
}

MAX_ATTRIBUTE_LENGTH = max(len(key) for key in ATTRIBUTES)

# Volatile globals
originalFileBeforeChange = None  # The first backup in this run
stored_passwords = None          # The dictionary of password instances


def readToDict(encryption_password):
    """Reads the encrypted file and parses the json into a dict of
    dicts containing attributes about each entry.

    {
        "Gmail": {"Password":"not this", "Email":...},
        "Facebook": {},
        "Youtube": {}, ...
    }

    Stores the dict of passwords in the global stored_passwords."""
    if not isfile(STORED_FILE_PATH):
        passwords = {}  # If there is no file then return empty list
    else:
        raw = utils.decryptFromFile(STORED_FILE_PATH, encryption_password
                                    ).decode()
        passwords = json.loads(raw)
    global stored_passwords
    stored_passwords = passwords


def writeDictToFile():
    """Takes a list of dictionaries as in readToList(), strigifies it with
    JSON and then writes to an encrypted file."""
    backupFile = time.strftime(".backup-%Y%m%d-%H%M%S.enc")
    global originalFileBeforeChange
    if originalFileBeforeChange is None:
        originalFileBeforeChange = backupFile
    if isfile(STORED_FILE_PATH):
        copyfile(STORED_FILE_PATH, backupFile)
    utils.encryptToFile(STORED_FILE_PATH, json.dumps(stored_passwords),
                        encryption_password)


def executeCommand(cmd):
    """Runs the command specified in the input string cmd."""
    directive, arg = ((cmd, None) if " " not in cmd
                      else tuple(cmd.split(" ", 1)))
    for key in COMMANDS:
        if key.startswith(directive):
            if directive == "list":
                return display_list()
            if directive == "help":
                return display_help()
            if directive == "show":
                return display_show(arg)
            if directive == "set":
                return display_set(arg)
            if directive == "undo":
                return undo()
            if directive == "exit":
                global running
                running = False
                return
            if directive == "remove":
                return display_remove(arg)
            if directive == "copy":
                return display_copy(arg)
    print("Unrecognised Command, try 'help'.")


def fmtAttribute(attr):
    "Right pads attribute by the largest attribute."
    return ("{:" + str(MAX_ATTRIBUTE_LENGTH) + "}").format(attr)


def fmtCommand(cmd):
    "Right pads command by the largest command."
    return ("{:" + str(MAX_COMMAND_LENGTH) + "}").format(cmd)


def display_list():
    """Given a dict of password dicts, it displays a list of their
    titles"""
    for key in stored_passwords:
        print(key)


def display_help():
    "Shows a list of possible commands"
    for cmd, desc in COMMANDS.items():
        print("{} {}".format(fmtCommand(cmd), desc))


def display_show(title):
    "Shows info about a given title"
    if title is None:
        print("Nothing given to show")
        return
    if title in stored_passwords:
        data = stored_passwords[title]
        for attribute in ATTRIBUTES:
            if attribute == "Title":
                continue
            val = ("-" if attribute not in data
                   else "********" if attribute == "Password"
                   else data[attribute])
            print("{} {}".format(fmtAttribute(attribute), val))
    else:
        print("Title not found in stored passwords.")


def display_set(title):
    "Sets data for a given title"
    if title is None:
        print("Nothing given to set")
        return
    if " " in title:
        print("Title can't have space in!")
    updated = False
    if title in stored_passwords:
        data = stored_passwords[title]
    else:
        data = {}
        updated = True
    print("Setting data for {}, leave blank for no entry or "
          "old value.".format(title))
    for attribute in ATTRIBUTES:
        if attribute == "Password":
            print("Enter password twice.")
            newPass1 = getpass.getpass()
            if newPass1 == "":
                continue
            newPass2 = getpass.getpass()
            while newPass1 != newPass2:
                print("Passwords don't match try again.")
                newPass1 = getpass.getpass()
                if newPass1 == "":
                    break
                newPass2 = getpass.getpass()
            if newPass1 != "":
                print(" Set password")
                updated = True
                data[attribute] = newPass1
        elif attribute != "Title":
            val = "-" if attribute not in data else data[attribute]
            newVal = input("Update {} from {}:".format(attribute, val))
            if newVal != "":
                updated = True
                print(" Set {}: {} > {}".format(fmtAttribute(attribute),
                                                val, newVal))
                data[attribute] = newVal
    if updated:
        stored_passwords[title] = data
        writeDictToFile()
        print("Updated")
    else:
        print("Not updated, not saving.")


def undo():
    "Restores store file to first backup made this time it was opened."
    if originalFileBeforeChange is None:
        print("Nothing to undo")
    else:
        copyfile(originalFileBeforeChange, STORED_FILE_PATH)
        readToDict(encryption_password)
        print("Reset to before any changes this log in.")


def display_remove(title):
    "Removes title from the stored passwords"
    if title is None:
        print("Nothing to remove.")
    try:
        del stored_passwords[title]
    except KeyError:
        print("Title not in stored.")
    else:
        writeDictToFile()
        print("Removed")


def display_copy(args):
    """Takes a string '<title> [attribute]' and copies title's attribute
    value to the clipboard. If no attribute is given then 'Password' is
    the default"""
    args = args.split(" ", 1)
    if len(args) == 1:
        args.append("Password")
    title, attribute = tuple(args)
    try:
        pyperclip.copy(stored_passwords[title][attribute])
    except KeyError:
        print("Title isn't stored or doesn't have that attribute.")
    print("Copied {} of {} to clipboard.".format(attribute, title))


if __name__ == "__main__":
    print(__doc__)
    try:
        while stored_passwords is None:
            encryption_password = getpass.getpass()
            try:
                readToDict(encryption_password)
            except utils.VerificationError:
                print("Wrong password. Try again.")
        running = True
        while running:
            executeCommand(input("> "))
    except (KeyboardInterrupt, EOFError):
        print()  # Incase in password input...
        print("Exit...")
