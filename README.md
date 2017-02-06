#Keeper of critical data

This program can encrypt critical data file and store it in html format.
If you copy this html files into web server, web crawlers can find their
and store into cache of web search engine.

If you use in title of result pages unique text, you can find this cached pages
with help of web search engine and decrypt this data. Also you can use
web archives (such as [https://archive.org/web/](https://archive.org/web/))
for find previous versions of this pages.

##Usage

_The Keeper_ consists of tree part:
* generator of public key from passphrase;
* encryption script;
* decryption script.

###Generator of public key from passphrase

_The Keeper_ encrypt data using random keys and AES 256 algorithm. Random encryption
keys stored in result as parameters for Diffie–Hellman key exchange algorithm.
Encryption script uses the previously saved p and g parameters from RFC 5114,
and public key generated from passphrase.

For these purposes is the **get_public_key.py** script. It generates the public key
and stores it together with the parameters p and g for Diffie–Hellman key exchange
algorithm.

Use argument **-h** for get help about usage this script.

Typical usage:

**`python get_public_key.py -f public.key`**

**`python3 get_public_key.py -f public.key`**

In this sample script display prompt for entering passphrase and save generated
public key into file public.key. The public key is not secret. 

###Encryption script

_The Keeper_ saves content of file in one or more html files. This task doing
**encrypt_file.py** script.

Use argument **-h** for get help about usage this script.

Typical usage:

**`python3 encrypt_file.py -c 16384 -t "uniquekeytext for title" public.key
/path/to/source.file /path/to/webserver/dir`**

**`python encrypt_file.py -c 16384 -t "uniquekeytext000 for title" public.key
/path/to/source.file /path/to/webserver/dir`**

In this sample script divide file on chunks, that have 16384 bytes,
encrypt their using public key from public.key file and save html files
into /path/to/webserver/dir directory. Use the **-t** argument for define
unique text that can be find by web search engine
(**uniquekeytext000** in this sample).

Besides encrypted data html files contains sources of scrips that
needed to decrypt data.

You can store additional information into html template file (**out_file.tmpl**).

You can use **-temp** argument for specify template file for **encrypt_files.py**
script.

###Decryption script

You can download encrypted pages and use **decrypt_file.py** script for
decrypt and save original file.

Use argument **-h** for get help about usage this script.

Typical usage:

**`python3 decrypt_file.py /path/to/html/files/dir /path/to/destination.file`**

**`python3 decrypt_file.py /path/to/html/files/dir /path/to/destination.file`**

In this sample script display prompt for entering passphrase, generate private
key for Diffie–Hellman key exchange algorithm and decrypt content of html files
in **/path/to/html/files/dir** directory.



