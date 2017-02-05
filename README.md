#Keeper of critical data

This program can encrypt critical data file and store it in html format.
If you copy this html files into web server, web crawlers can find their
and store into cache of web search engine.

If you use in title of result pages unique text, you can find this cached pages
with help of web search engine and decrypt this data. Also you can use
web archives (such as [https://archive.org/web/](https://archive.org/web/))
for find previous versions of this pages.

##Usage

Keeper consists of four part:
* generator of public key from passphrase;
* encryption script;
* decryption script;
* integrity test script.

###Generator of public key from passphrase

_The Keeper_ encrypt data using random keys and AES 256 algorithm. Random encryption
keys stored encrypted in result. For this encryption used PKCS1_OAEP algorithm
and public RSA key, that generated from passphrase.

For these purposes is the **get_public_key.py** script. It generates the public key
in PEM format from passphrase. For this script required **Python 3** for
correct working.

Use argument **-h** for get help about usage this script.

Typical usage:

**python3 get_public_key.py -b 4096 -f public.pem**

In this sample script display prompt for entering passphrase and save generated
4096 bit RSA public key into file public.pem. The public key is not secret. 

###Encryption script

_Required Python 2.7 or Python 3_

_The Keeper_ saves content of file in one or more html files. This task doing
**encrypt_file.py** script.

Use argument **-h** for get help about usage this script.

Typical usage:

**python3 encrypt_file.py -c 16384 -t "uniquekeytext for title" public.pem
/path/to/source.file /path/to/webserver/dir**

**python encrypt_file.py -c 16384 -t "uniquekeytext000 for title" public.pem
/path/to/source.file /path/to/webserver/dir**

In this sample script divide file on chunks, that have 16384 bytes,
encrypt their using public key from public.pem file and save html files
into /path/to/webserver/dir directory. Use the **-t** argument for define
unique text that can be find by web search engine
(**uniquekeytext000** in this sample).

Besides encrypted data html files contains sources of scrips that
needed to decrypt data.

###Decryption script

You can download encrypted pages and use **decrypt_file.py** script for
decrypt and save original file. For this script required **Python 3** for
correct working. Usually html files contain the necessary decryption scripts.

Use argument **-h** for get help about usage this script.

Typical usage:

**python3 decrypt_file.py -b 4096 /path/to/html/files/dir /path/to/destination.file**

In this sample script display prompt for entering passphrase, generate private
RSA key and decrypt content of html files in **/path/to/html/files/dir** directory.

###Integrity test script
**Crypto.PublicKey.RSA.generate** from **PyCrypto** may operate differently from
the random number generator. If you use a passphrase more appropriate other
algorithms - **Diffie-Hellman** (DH) or **Elliptic curve Diffie–Hellman** (ECDH).
However, at the beginning of 2017 there are no stable open source implementation
of these algorithms in Python. Therefore, for this projects selected RSA algorithm,
which is implemented in a library PyCrypto. But this library does not guarantee
that the same keys are derived using the same random number generators,
as it is not part of any standard. The random number generator used in this
project gives identical results for identical passphrases.
But Crypto.PublicKey.RSA.generate may gives various results even
using this generator. And this is a problem.

Typically RSA key generation method gives the same results when using the same
version Python and PyCrypto. There is a simple way to check that the key
generation environment is equivalent to decryption environment.
The equivalence of the environment means that when generating the keys for
the same passphrase will be obtained the same results.

This path consists of three steps.

####Step 1

In the same environment where you use a script, run **integrity_test.py** script:

**python3 integrity_test.py -c -b 4096 /path/to/test.pem**

This creates the public key file, which will later be used to test the integrity.

####Step 2

Copy PEM file that created on step 1, into the computer that are you using
for encryption. Also copy integrity_test.py script into the _keeper_ script
directory on this computer. Use **encrypt_file.py** with additional
argument **-v /path/to/test.pem** .
This will add content **test.pem** file and source of **integrity_test.py** script
into destination html files.

####Step 3

Before decryption, you can verify that the current environment allows you
to get the correct result. Extract test.pem data and **integrity_test.py** script
from html file, and run **integrity_test.py** script:

**python3 integrity_test.py -b 4096 /path/to/test.pem**

If you got the result **"Test: PASSED!"**, the current environment is
suitable for the decryption operation.

##Remarks

You can store version numbers of the Python and
the PyCrypto which used for public key generation into html template
file (out_file.tmpl). Also you can store other information (about the operating
system, for example).

You can use **-temp** argument for specify template file for **encrypt_files.py**
script.
