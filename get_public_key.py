# Copyright (C) 2017 Maxim Avilov (https://github.com/maxavilov)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import print_function

import argparse
import sys
from base64 import b64encode
from getpass import getpass

import diffie_hellman

parser = argparse.ArgumentParser(
    description="Generate Diffie-Hellman public key from passphrase and output it to the file.")
parser.add_argument("-f", "--file", help="File name for output public key")
parser.add_argument("-p", "--passphrase",
                    help="Passphrase. Warning: Using a password on the command line interface can be insecure.")
args = parser.parse_args()

if args.passphrase is None:
    passphrase = getpass("Enter passphrase:")
    passphrase_again = getpass("Enter passphrase again:")
    if passphrase != passphrase_again:
        sys.exit("Passphrases are not identical!")
else:
    print("Warning: Using a password on the command line interface can be insecure.")
    passphrase = args.passphrase

print("Generate Diffie-Hellman public key...")
public_key = b64encode(diffie_hellman.get_packed_public_from_passphrase(passphrase)).decode()
public_key_for_out = "-------- BEGIN PUBLIC DIFFIE-HELLMAN AND PARAMS --------\n"
for line in [public_key[i:i + 80] for i in range(0, len(public_key), 80)]:
    public_key_for_out += line + "\n"
public_key_for_out += "--------  END PUBLIC DIFFIE-HELLMAN AND PARAMS  --------"

if args.file is None:
    print()
    print(public_key_for_out)
else:
    try:
        with open(args.file, 'w') as file:
            file.write(public_key_for_out)
    except IOError:
        sys.exit("Can't output public key to file - IOError!")
print()
print("Operation successful complete!")
