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

from .base import __version__, __version_info__, armor, dearmor, pad, unpad, aes_pad_key

try:
    from .fields import *
except ImportError:
    pass
