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
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES


class RsaFromPassphrase:
    """The class that generates the RSA key from the passphrase"""

    def __init__(self, passphrase, bits=4096):
        def pseudo_rand_func(n):
            return self.rand_from_aes_rand(n)
        if sys.version_info.major < 3:
            sys.exit("Your Python interpreter is too old. Must use python 3 or greater.")
        self.master_key = PBKDF2(passphrase.encode('utf-8'),
                                 "HPqbk76Su8adA7rsctq3".encode('utf-8'), dkLen=32, count=100000)
        self.buffer = bytes(4096)
        self.cipher = AES.new(self.master_key, AES.MODE_CBC, bytes(16))
        self.buffer = self.cipher.encrypt(self.buffer)
        self.buffer_pos = 0
        self.RSA_key = RSA.generate(bits, randfunc=pseudo_rand_func, e=65537)

    def rand_from_aes_rand(self, n):
        need_bytes = n
        result = bytes(0)
        while need_bytes > 0:
            if 4096 - self.buffer_pos > 0:
                if need_bytes > 4096 - self.buffer_pos:
                    result += self.buffer[self.buffer_pos:4096]
                    need_bytes -= 4096 - self.buffer_pos
                    self.buffer_pos = 4096
                else:
                    result += self.buffer[self.buffer_pos:self.buffer_pos+need_bytes]
                    self.buffer_pos += need_bytes
                    need_bytes = 0
            else:
                self.buffer = self.cipher.encrypt(self.buffer)
                self.buffer_pos = 0
        return result

    def get_rsa_key(self):
        return self.RSA_key

    def get_public_pem(self):
        return self.RSA_key.publickey().exportKey('PEM').decode('utf-8')
