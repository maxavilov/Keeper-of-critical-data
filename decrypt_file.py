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
import os
import sys
from base64 import b64decode
from getpass import getpass
from lxml.html import fromstring

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA384

import diffie_hellman


def get_str_between_markers(src_str, begin, end):
    begin_idx = src_str.index(begin) + len(begin)
    end_idx = src_str.index(end, begin_idx)
    return src_str[begin_idx:end_idx].replace("\n", "")

parser = argparse.ArgumentParser(description="Decrypt files by key generated from passphrase and Diffie-Hellman params")
parser.add_argument("-i", "--index", default="index.html", help="Index (first) file name (default index.html)")
parser.add_argument("-p", "--prefix", default="", help="Chunk file name prefix (default empty string)")
parser.add_argument("source", help="Source directory that contain files for decrypt")
parser.add_argument("destination", help="Destination file name")
args = parser.parse_args()

passphrase = getpass("Enter passphrase:")  # Get passphrase
print("Generate secret...")
secret = diffie_hellman.passphrase_to_secret(passphrase)

print("Decrypt...")
try:
    with open(args.destination, 'wb') as destination_file:
        current_chunk_idx = 1
        file_hash = SHA256.new()
        while True:
            if current_chunk_idx == 1:
                source_file_name = os.path.join(args.source, args.index)
            else:
                source_file_name = os.path.join(args.source, args.prefix + str(current_chunk_idx) + ".html")
            if not os.path.isfile(source_file_name):
                sys.exit("Can't find source file: " + source_file_name)
            try:
                with open(source_file_name, 'r') as source_file:
                    src_content = fromstring(source_file.read())
            except IOError:
                sys.exit("Can't read source file: " + source_file_name)
            digest_tag = src_content.find('.//*[@id="digest"]')
            if digest_tag is None or digest_tag.text is None:
                sys.exit("Chunk file (%s) has wrong content (digest not present)!" % source_file_name)
            if current_chunk_idx == 1:
                digest = b64decode(digest_tag.text)
            else:
                if digest != b64decode(digest_tag.text):
                    sys.exit("Chunk file (%s) has wrong content (digest has different from first chunk value)!"
                             % source_file_name)
            encrypted_data_and_key_tag = src_content.find('.//*[@id="data"]')
            if encrypted_data_and_key_tag is None or encrypted_data_and_key_tag.text is None:
                sys.exit("Chunk file (%s) has wrong content (data not present)!" % source_file_name)
            try:
                key_data_str = get_str_between_markers(encrypted_data_and_key_tag.text,
                                                       "-------- BEGIN DH PUBLIC --------",
                                                       "--------  END DH PUBLIC  --------")
                if not key_data_str:
                    raise ValueError("Empty key data!")
            except ValueError:
                sys.exit("Chunk file (%s) has wrong content (invalid key data)!" % source_file_name)
            try:
                key_data = b64decode(key_data_str)
                shared_key, _ = diffie_hellman.get_shared_key_and_packed_public(secret, key_data)
                key_src = SHA384.new()
                key_src.update(shared_key)
                key_and_iv = key_src.digest()
                chunk_key = key_and_iv[:32]  # AES 256 key
                chunk_iv = key_and_iv[-16:]  # Extract chunk AES IV
                cipher = AES.new(chunk_key, AES.MODE_CFB, chunk_iv)
            except ValueError:
                sys.exit("Chunk file (%s) has wrong content (can't extract key data)!" % source_file_name)
            try:
                data_str = get_str_between_markers(encrypted_data_and_key_tag.text,
                                                   "-------- BEGIN DATA --------",
                                                   "--------  END DATA  --------")
                if not data_str:
                    raise ValueError("Empty data!")
            except ValueError:
                sys.exit("Chunk file (%s) has wrong content (invalid data)!" % source_file_name)
            data = cipher.decrypt(b64decode(data_str))
            destination_file.write(data)  # Write decrypted data to destination file
            file_hash.update(data)
            # If current digest equal the file digest, the end of file found
            # Else do process next chunk
            if file_hash.digest() == digest:
                break
            else:
                current_chunk_idx += 1
    print('Operation successful complete!')
except IOError:
    sys.exit("Can't write to destination file")
