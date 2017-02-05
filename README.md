#Keeper of critical data

This program can encrypt critical data file and store it in html format.
If you copy this html files into web server, web crawlers can find their
and store into cache of web search engine.

If you use in title of result pages unique text, you can find this cached pages
with help of web search engine and decrypt this data. Also you can use
web archives (such as [https://archive.org/web/](https://archive.org/web/))
for find previous versions of this pages.

##Usage

Keeper consists of three part:
* generator of public key from passphrase;
* encryption script;
* decryption script;

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
**encrypt_files.py** script.

Use argument **-h** for get help about usage this script.

Typical usage:

**python3 encrypt_files.py -c 16384 -t "uniquekeytext for title" public.pem
/path/to/source.file /path/to/webserver/dir**

**python encrypt_files.py -c 16384 -t "uniquekeytext000 for title" public.pem
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

##Remarks

**Crypto.PublicKey.RSA** from **PyCrypto** may operate differently from the random
number generator. Recommended use Python 3 and PyCrypto 2.6.1 for consistent results.
Differences may occur during RSA key generation by **get_public_key.py** and
**decrypt_file.py** scripts. You can store version numbers of the Python and
the PyCrypto which used for public key generation into html template
file (out_file.tmpl). Also you can store other information (about the operating
system, for example).

You can use **-temp** argument for specify template file for **encrypt_files.py**
script.
