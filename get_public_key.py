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
import sys
import argparse
from getpass import getpass
from rsa_from_passphrase import RsaFromPassphrase

if sys.version_info.major < 3:
    sys.exit("Your Python interpreter is too old. Must use python 3 or greater.")

parser = argparse.ArgumentParser(description="Generate RSA key from passphrase and output it in PEM format.")
parser.add_argument("-b", "--bits", type=int, default=0, help="Number of RSA key bits")
parser.add_argument("-f", "--file", help="File name for output public key in PEM format")
parser.add_argument("-p", "--passphrase", help="Passphrase. Warning: Using a password on the command line interface can be insecure.")
args = parser.parse_args()

if args.passphrase is None:
    passphrase = getpass("Enter passphrase:")
    passphrase_again = getpass("Enter passphrase again:")
    if passphrase != passphrase_again:
        sys.exit("Passphrases are not identical!")
else:
    print("Warning: Using a password on the command line interface can be insecure.")
    passphrase = args.passphrase

if args.bits == 0:
    try:
        bits = int(input("Number of RSA key bits [4096]:"))
    except ValueError:
        bits = 4096
else:
    bits = args.bits

if bits < 1024 or bits % 256 != 0:
    sys.exit("Wrong bits value! It must be a multiple of 256, and no smaller than 1024.")

print("Generate %d bits RSA key..." % bits)
RSA_key = RsaFromPassphrase(passphrase, bits)

if args.file is None:
    print()
    print(RSA_key.get_public_pem())
else:
    try:
        with open(args.file, 'w') as file:
            file.write(RSA_key.get_public_pem())
    except IOError:
        sys.exit("Can't output public key to file - IOError!")
print()
print("Operation successful complete!")
