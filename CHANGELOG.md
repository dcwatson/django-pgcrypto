# Changelog for django-pgcrypto

## 3.0.3 (2025-02-04)

* Added `iexact` lookup (https://github.com/dcwatson/django-pgcrypto/pull/39)


## 3.0.2

* Added `Encrypt` and `Decrypt` Django functions (https://github.com/dcwatson/django-pgcrypto/pull/36)
* Added `contains`, `icontains`, `startswith`, `istartswith`, `endswith`, and `iendswith` filter support (https://github.com/dcwatson/django-pgcrypto/pull/37)


## 3.0.1

* Properly handle query expressions, fixing e.g. bulk_update (https://github.com/dcwatson/django-pgcrypto/pull/35)


## 3.0.0

* Moved to pyproject.toml
* Dropped support for Blowfish (https://github.com/dcwatson/django-pgcrypto/pull/34)
* Updated CI for supported versions of Python and Django
* Coalesce encrypted text-like fields to the empty string, use NULLIF for dearmor (https://github.com/dcwatson/django-pgcrypto/pull/30)
* Support `__in` lookups (https://github.com/dcwatson/django-pgcrypto/pull/33)


## 2.0.0

* Updated for Python 3 and Django 2.2+ (along with actual CI testing)
* Switched from PyCrypto to Cryptography for encryption/decryption
* Fixed filtering on blank encrypted fields (https://github.com/dcwatson/django-pgcrypto/pull/23)


## 1.4.0

* Updated for Django 1.10 compatibility (by removing SubfieldBase)
