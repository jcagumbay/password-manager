# Password manager

Passphrase protected file encryption/decryption.

# How to use

**Encryption:**
```
python crypto.py -e your-passphrase ./file-to-encrypt
```
this will generate *encrypted.txt* on the same directory.

**Decryption:**
```
python crypto.py -d your-passphrase ./encrypted-file
```
this will generate *decrypted.txt* on the same directory.
