# -*- coding: utf-8 -*-
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
from rsa_from_passphrase import RsaFromPassphrase


if sys.version_info.major < 3:
    sys.exit("Your Python interpreter is too old. Must use python 3 or greater.")

parser = argparse.ArgumentParser(description="Generate PEM file for integrity test or test integrity using PEM file")
parser.add_argument("-b", "--bits", type=int, default=4096, help="Number of RSA key bits")
parser.add_argument("-c", "--create", action="store_true",
                    help="Create PEM file mode, if not set do test integrity using PEM file")
parser.add_argument("pem_file", help="PEM file name")
args = parser.parse_args()

if args.bits < 1024 or args.bits % 256 != 0:
    sys.exit("Wrong bits value! It must be a multiple of 256, and no smaller than 1024.")
print("Generate %d bits RSA key..." % args.bits)
RSA_key = RsaFromPassphrase("ABCDabcdАБВГабвг", args.bits)

if args.create:
    try:
        with open(args.pem_file, 'w') as file:
            file.write(RSA_key.get_public_pem())
    except IOError:
        sys.exit("Can't output public key to a file - IOError!")
    print("Operation successful complete!")
else:
    try:
        with open(args.pem_file, 'r') as file:
            key_data = file.read().replace("\n", "").replace(" ", "").replace("\t", "")
            if key_data == RSA_key.get_public_pem().replace("\n", "").replace(" ", "").replace("\t", ""):
                print("Test: PASSED!")
            else:
                sys.exit("Test: FAILED!")
    except IOError:
        sys.exit("Can't read public key from a file - IOError!")
