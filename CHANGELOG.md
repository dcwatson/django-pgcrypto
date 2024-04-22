# Changelog for django-pgcrypto

## 3.0.0

* Moved to pyproject.toml
* Dropped support for Blowfish (#34)
* Updated CI for supported versions of Python and Django
* Coalesce encrypted text-like fields to the empty string, use NULLIF for dearmor (#30)
* Support `__in` lookups (#33)


## 2.0.0

* Updated for Python 3 and Django 2.2+ (along with actual CI testing)
* Switched from PyCrypto to Cryptography for encryption/decryption
* Fixed filtering on blank encrypted fields (#23)


## 1.4.0

* Updated for Django 1.10 compatibility (by removing SubfieldBase)
