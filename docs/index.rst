.. django-pgcrypto documentation master file, created by
   sphinx-quickstart on Mon May 12 23:14:40 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to django-pgcrypto's documentation!
===========================================

Quickstart
----------

There are several encrypted versions of Django fields that you can use (mostly) as you would use a normal Django field::

    from django.db import models
    import pgcrypto
    
    class Employee (models.Model):
        name = models.CharField(max_length=100)
        ssn = pgcrypto.EncryptedTextField()
        pay_rate = pgcrypto.EncryptedDecimalField()
        date_hired = pgcrypto.EncryptedDateField(cipher='Blowfish', key='datekey')

If not specified when creating the field (as in the ``date_hired`` field above), fields are encrypted according to the following settings:

``PGCRYPTO_VALID_CIPHERS`` (default: ``('AES', 'Blowfish')``):
    A list of valid PyCrypto cipher names. Currently only AES and Blowfish are supported, so this setting is mostly for future-proofing.

``PGCRYPTO_DEFAULT_CIPHER`` (default: ``'AES'``):
    The PyCrypto cipher to use when encrypting fields.

``PGCRYPTO_DEFAULT_KEY`` (default: ``''``):
    The default key to use for encryption.


Contents:

.. toctree::
   :maxdepth: 2



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

