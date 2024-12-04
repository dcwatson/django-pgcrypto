![CI](https://github.com/dcwatson/django-pgcrypto/workflows/CI/badge.svg)

# django-pgcrypto

A set of utility functions for dealing with ASCII Armor (http://www.ietf.org/rfc/rfc2440.txt) and padding, and a collection of Django field classes that utilize these functions in a way that is compatible with pgcrypto functions.

## Installation

`pip install django-pgcrypto`

## Quickstart

There are several encrypted versions of Django fields that you can use (mostly) as you would use a normal Django field:

```python
from django.db import models
import pgcrypto

class Employee (models.Model):
    name = models.CharField(max_length=100)
    ssn = pgcrypto.EncryptedTextField()
    pay_rate = pgcrypto.EncryptedDecimalField()
    date_hired = pgcrypto.EncryptedDateField(key="datekey", auto_now_add=True)
```

If not specified when creating the field (as in `ssn` and `pay_rate` above), fields are encrypted according to the following settings:

* `PGCRYPTO_DEFAULT_CIPHER` (only `aes` is currently supported) - The default algorithm to use when encrypting fields.
* `PGCRYPTO_DEFAULT_KEY` (default: `settings.SECRET_KEY`) - The default key to use for encryption.

You must also make sure the pgcrypto extension is installed in your database. Django makes this easy with a [CryptoExtension](https://docs.djangoproject.com/en/dev/ref/contrib/postgres/operations/#cryptoextension) migration.

## Querying

It is possible to filter on encrypted fields as you would normal fields via `exact`, `gt`, `gte`, `lt`, `lte`, `contains`, `icontains`, `startswith`, `istartswith`, `endswith`, and `iendswith` lookups. For example, querying the model above is possible like so:

```python
Employee.objects.filter(date_hired__gt="1981-01-01", salary__lt=60000)
```

## Caveats

This library encrypts and encodes data in a way that works with pgcrypto's [raw encryption functions](https://www.postgresql.org/docs/current/pgcrypto.html#id-1.11.7.34.8). All the warnings there about using direct keys and the lack of integrity checking apply here.

This library also predates Django's [BinaryField](https://docs.djangoproject.com/en/dev/ref/models/fields/#binaryfield), which is why the fields are essentially `TextField`s that store armored encrypted data. This may or may not be ideal for your application, and a hypothetical future version might include a switch to store binary data.
