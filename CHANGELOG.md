# Changelog for django-pgcrypto

## 2.0.0

* Updated for Python 3 and Django 2.2+ (along with actual CI testing)
* Switched from PyCrypto to Cryptography for encryption/decryption
* Fixed filtering on blank encrypted fields (#23)

## 1.4.0

* Updated for Django 1.10 compatibility (by removing SubfieldBase)
