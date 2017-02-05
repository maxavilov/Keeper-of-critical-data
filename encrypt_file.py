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
import sys
import os
import argparse
import base64
import struct
from array import array
from datetime import datetime
from lxml.html import fromstring

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP


parser = argparse.ArgumentParser(description="Encrypt the file by RSA public key and output result to html files.")
parser.add_argument("-t", "--title", default="Encrypted file content", help="Title for destination pages")
parser.add_argument("-i", "--index", default="index.html", help="Index file name (default index.html)")
parser.add_argument("-temp", "--template", default="", help="Template file")
parser.add_argument("-c", "--chunk_size", type=int, default=32768, help="Chunk size")
parser.add_argument("-p", "--prefix", default="", help="Chunk file name prefix (default empty string)")
parser.add_argument("-f", "--force", action="store_true", help="Force update destination files")
parser.add_argument("key", help="Public key PEM file")
parser.add_argument("file", help="Source file for encryption")
parser.add_argument("destination", help="Destination directory")
args = parser.parse_args()

script_dir_path = os.path.dirname(os.path.realpath(__file__))

# Read software source files
try:
    with open(os.path.join(script_dir_path, "tails_python.sh"), 'r') as file:
        tails_python = file.read().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    with open(os.path.join(script_dir_path, "rsa_from_passphrase.py"), 'r') as file:
        rsa_from_passphrase = file.read().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    with open(os.path.join(script_dir_path, "decrypt_file.py"), 'r') as file:
        decrypt_file = file.read().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
except IOError:
    sys.exit("Can't read software source files")

timestamp = datetime.utcnow().isoformat()

# Read RSA public key
try:
    with open(args.key, 'r') as file:
        key_data = file.read()
except IOError:
    sys.exit("Can't read public key file")
try:
    public_key = RSA.importKey(key_data)
except ValueError:
    sys.exit("Invalid public key file content!")

# Check if source file has changes
if not args.force:
    index_file_name = os.path.join(args.destination, args.index)
    if os.path.isfile(index_file_name):
        try:
            with open(index_file_name, 'r') as file:
                index_content = fromstring(file.read())
                digest_tag = index_content.find('.//*[@id="digest"]')
                if digest_tag is not None and digest_tag.text is not None:
                    digest = base64.b64decode(digest_tag.text)
                    file_hash = SHA256.new()
                    chunk_size = 4096
                    try:
                        with open(args.file, 'rb') as source_file:
                            while True:
                                chunk = source_file.read(chunk_size)
                                if len(chunk) == 0:
                                    break
                                file_hash.update(chunk)
                            if file_hash.digest() == digest:
                                print('Source file is not changed. Use --force for force update destination files.')
                                sys.exit()
                    except IOError:
                        sys.exit("Can't read from source file!")
        except IOError:
            sys.exit("Can't read from destination index file!")

# Read template file
if args.template == "":
    template_path = os.path.join(script_dir_path, "out_file.tmpl")
else:
    template_path = args.template
try:
    with open(template_path, 'r') as file:
        template = file.read()
except IOError:
    sys.exit("Can't read template file")

# Process source file
try:
    source_size = os.path.getsize(args.file)
    chunk_size = args.chunk_size
    current_chunk_idx = 1
    file_hash = SHA256.new()
    with open(args.file, 'rb') as source_file:
        while True:
            chunk = source_file.read(chunk_size)
            if len(chunk) == 0:
                break
            file_hash.update(chunk)
            padding_len = 16 - len(chunk) % 16  # padding for AES
            if padding_len == 16:
                padding_len = 0
            chunk += bytes(array('B', [i for i in range(0, padding_len)]).tostring())
            chunk_key = Random.new().read(32)  # AES 256 key for chunk
            chunk_iv = Random.new().read(16)   # IV for AES encryption
            cipher = AES.new(chunk_key, AES.MODE_CBC, chunk_iv)
            encrypted = base64.b64encode(cipher.encrypt(chunk)).decode()
            cipher_for_key = PKCS1_OAEP.new(public_key)
            encrypted_key_iv = base64.b64encode(cipher_for_key
                                                .encrypt(chunk_key + chunk_iv
                                                         + struct.pack('B', padding_len))).decode()
            # Out data to temporary file
            if current_chunk_idx == 1:
                result_file_name = os.path.join(args.destination, "." + args.index + ".tmpenc")
            else:
                result_file_name = os.path.join(args.destination, "." + args.prefix + str(current_chunk_idx)
                                                + ".html.tmpenc")
            data = "-------- BEGIN KEY --------\n"
            for line in [encrypted_key_iv[i:i+80] for i in range(0, len(encrypted_key_iv), 80)]:
                data += line + "\n"
            data += "--------  END KEY  --------\n-------- BEGIN DATA --------\n"
            for line in [encrypted[i:i+80] for i in range(0, len(encrypted), 80)]:
                data += line + "\n"
            data += "--------  END DATA  --------\n"
            try:
                with open(result_file_name, 'w') as tmp_file:
                    tmp_file.write(template.format(title=args.title + " [" + str(current_chunk_idx) + "]",
                                                   timestamp=timestamp, digest="{digest}",
                                                   links="{links}", data=data,
                                                   tails_python=tails_python,
                                                   rsa_from_passphrase=rsa_from_passphrase,
                                                   decrypt_file=decrypt_file))
            except IOError:
                sys.exit("Error write to temporary file!")
            current_chunk_idx += 1
    digest = base64.b64encode(file_hash.digest()).decode()
    for i in range(1, current_chunk_idx):
        if i == 1:
            tmp_file_name = os.path.join(args.destination, "." + args.index + ".tmpenc")
            destination_file_name = os.path.join(args.destination, args.index)
            links = '1'
        else:
            tmp_file_name = os.path.join(args.destination, "." + args.prefix + str(i) + ".html.tmpenc")
            destination_file_name = os.path.join(args.destination, args.prefix + str(i) + ".html")
            links = '<a href="' + args.index + '">1</a>'
        for j in range(2, current_chunk_idx):
            if i == j:
                links += '&nbsp;' + str(j)
            else:
                links += '&nbsp;<a href="' + args.prefix + str(j) + '.html">' + str(j) + '</a>'
        try:
            with open(tmp_file_name, 'r') as tmp_file:
                content = tmp_file.read()
        except IOError:
            sys.exit("Can't read temporary file!")
        try:
            with open(destination_file_name, 'w') as destination_file:
                destination_file.write(content.format(digest=digest, links=links))
        except IOError:
            sys.exit("Can't write to destination file!")
        try:
            os.remove(tmp_file_name)
        except OSError:
            sys.exit("Can't delete temporary file!")
    print('Operation successful complete!')
except OSError:
    sys.exit("Invalid source file!")
except IOError:
    sys.exit("Can't read from source file!")
