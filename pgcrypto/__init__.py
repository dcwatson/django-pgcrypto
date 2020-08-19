# django-pgcrypto
# Dan Watson
#
# A pure python implementation of ASCII Armor, along with various
# padding and unpadding functions, all compatible with pgcrypto.
#
# Additionally, this module defines Django fields that automatically
# encrypt and armor (and decrypt and dearmor) values for storage
# in text fields. Values stored using these fields may be read by
# pgcrypto using decrypt(dearmor(col),...), and values stored by
# pgcrypto using armor(encrypt(col,...)) may be read by these fields.
#
# See http://www.ietf.org/rfc/rfc2440.txt for ASCII Armor specs.

from .base import __version__, __version_info__, aes_pad_key, armor, dearmor, pad, unpad

__all__ = ["__version__", "__version_info__", "aes_pad_key", "armor", "dearmor", "pad", "unpad"]

try:
    import django  # noqa: F401

    has_django = True
except ImportError:
    has_django = False

if has_django:
    from .fields import (
        EncryptedCharField,
        EncryptedDateField,
        EncryptedDateTimeField,
        EncryptedDecimalField,
        EncryptedEmailField,
        EncryptedIntegerField,
        EncryptedTextField,
    )

    __all__ += [
        "EncryptedCharField",
        "EncryptedDateField",
        "EncryptedDateTimeField",
        "EncryptedDecimalField",
        "EncryptedEmailField",
        "EncryptedIntegerField",
        "EncryptedTextField",
    ]
