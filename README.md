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
    date_hired = pgcrypto.EncryptedDateField(cipher="bf", key="datekey", auto_now_add=True)
```

If not specified when creating the field (as in `ssn` and `pay_rate` above), fields are encrypted according to the following settings:

* `PGCRYPTO_DEFAULT_CIPHER` (`aes` or `bf`, default: `aes`) - The default algorithm to use when encrypting fields.
* `PGCRYPTO_DEFAULT_KEY` (default: `settings.SECRET_KEY`) - The default key to use for encryption.

## Querying

It is possible to filter on encrypted fields as you would normal fields via `exact`, `gt`, `gte`, `lt`, and `lte` lookups. For example, querying the model above is possible like so:

```python
Employee.objects.filter(date_hired__gt='1981-01-01', salary__lt=60000)
```
