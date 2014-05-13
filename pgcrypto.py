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

__version_info__ = (1, 2, 0)
__version__ = '.'.join(str(i) for i in __version_info__)

try:
    import django
    from django import forms
    from django.conf import settings
    from django.core import validators
    from django.db import models
    from django.utils import timezone
    from django.utils.translation import ugettext_lazy as _
    has_django = True
except:
    has_django = False

import base64
import datetime
import decimal
import struct

CRC24_INIT = 0xB704CE
CRC24_POLY = 0x1864CFB

def ord_safe(ch):
    if isinstance(ch, int):
        return ch
    return ord(ch)

def crc24(data):
    crc = CRC24_INIT
    for byte in data:
        crc ^= (ord_safe(byte) << 16)
        for _i in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= CRC24_POLY
    return crc & 0xFFFFFF

def armor(data, versioned=True):
    """
    Returns a string in ASCII Armor format, for the given binary data. The
    output of this is compatiple with pgcrypto's armor/dearmor functions.
    """
    template = '-----BEGIN PGP MESSAGE-----\n%(headers)s%(body)s\n=%(crc)s\n-----END PGP MESSAGE-----'
    body = base64.b64encode(data)
    # The 24-bit CRC should be in big-endian, strip off the first byte (it's already masked in crc24).
    crc = base64.b64encode(struct.pack('>L', crc24(data))[1:])
    return template % {
        'headers': 'Version: django-pgcrypto %s\n\n' % __version__ if versioned else '',
        'body': body.decode('ascii'),
        'crc': crc.decode('ascii'),
    }

class BadChecksumError (Exception):
    pass

def dearmor(text, verify=True):
    """
    Given a string in ASCII Armor format, returns the decoded binary data.
    If verify=True (the default), the CRC is decoded and checked against that
    of the decoded data, otherwise it is ignored. If the checksum does not
    match, a BadChecksumError exception is raised.
    """
    lines = text.strip().split('\n')
    data_lines = []
    check_data = None
    started = False
    in_body = False
    for line in lines:
        if line.startswith('-----BEGIN'):
            started = True
        elif line.startswith('-----END'):
            break
        elif started:
            if in_body:
                if line.startswith('='):
                    # Once we get the checksum data, we're done.
                    check_data = line[1:5].encode('ascii')
                    break
                else:
                    # This is part of the base64-encoded data.
                    data_lines.append(line)
            else:
                if line.strip():
                    # This is a header line, which we basically ignore for now.
                    pass
                else:
                    # The data starts after an empty line.
                    in_body = True
    b64_str = ''.join(data_lines)
    # Python 3's b64decode expects bytes, not a string. We know base64 is ASCII, though.
    data = base64.b64decode(b64_str.encode('ascii'))
    if verify and check_data:
        # The 24-bit CRC is in big-endian, so we add a null byte to the beginning.
        crc = struct.unpack('>L', b'\0' + base64.b64decode(check_data))[0]
        if crc != crc24(data):
            raise BadChecksumError()
    return data

def unpad(text, block_size):
    """
    Takes the last character of the text, and if it is less than the block_size,
    assumes the text is padded, and removes any trailing zeros or bytes with the
    value of the pad character. See http://www.di-mgt.com.au/cryptopad.html for
    more information (methods 1, 3, and 4).
    """
    end = len(text)
    if end == 0:
        return text
    padch = ord_safe(text[end - 1])
    if padch > block_size:
        # If the last byte value is larger than the block size, it's not padded.
        return text
    while end > 0 and ord_safe(text[end - 1]) in (0, padch):
        end -= 1
    return text[:end]

def pad(text, block_size, zero=False):
    """
    Given a text string and a block size, pads the text with bytes of the same value
    as the number of padding bytes. This is the recommended method, and the one used
    by pgcrypto. See http://www.di-mgt.com.au/cryptopad.html for more information.
    """
    num = block_size - (len(text) % block_size)
    ch = '\0' if zero else chr(num)
    return text + (ch * num)

def aes_pad_key(key):
    """
    AES keys must be either 16, 24, or 32 bytes long. If a key is provided that is not
    one of these lengths, pad it with zeroes (this is what pgcrypto does).
    """
    if len(key) in (16, 24, 32):
        return key
    if len(key) < 16:
        return pad(key, 16, zero=True)
    elif len(key) < 24:
        return pad(key, 24, zero=True)
    else:
        return pad(key[:32], 32, zero=True)

if has_django:
    class BaseEncryptedField (models.Field):

        def __init__(self, *args, **kwargs):
            # Just in case pgcrypto and/or pycrypto support more than AES/Blowfish.
            valid_ciphers = getattr(settings, 'PGCRYPTO_VALID_CIPHERS', ('AES', 'Blowfish'))
            cipher_name = kwargs.pop('cipher', getattr(settings, 'PGCRYPTO_DEFAULT_CIPHER', 'AES'))
            assert cipher_name in valid_ciphers
            self.cipher_key = kwargs.pop('key', getattr(settings, 'PGCRYPTO_DEFAULT_KEY', ''))
            self.charset = 'utf-8'
            if cipher_name == 'AES':
                self.cipher_key = aes_pad_key(self.cipher_key)
            mod = __import__('Crypto.Cipher', globals(), locals(), [cipher_name], -1)
            self.cipher_class = getattr(mod, cipher_name)
            self.check_armor = kwargs.pop('check_armor', True)
            models.Field.__init__(self, *args, **kwargs)

        def get_internal_type(self):
            return 'TextField'

        def south_field_triple(self):
            """
            Describe the field to south for use in migrations.
            """
            from south.modelsinspector import introspector
            args, kwargs = introspector(self)
            return ("django.db.models.fields.TextField", args, kwargs)

        def get_cipher(self):
            """
            Return a new Cipher object for each time we want to encrypt/decrypt. This is because
            pgcrypto expects a zeroed block for IV (initial value), but the IV on the cipher
            object is cumulatively updated each time encrypt/decrypt is called.
            """
            return self.cipher_class.new(self.cipher_key, self.cipher_class.MODE_CBC, b'\0' * self.cipher_class.block_size)

        def is_encrypted(self, value):
            return isinstance(value, basestring) and value.startswith('-----BEGIN')

        def to_python(self, value):
            if self.is_encrypted(value):
                # If we have an encrypted (armored, really) value, do the following when accessing it as a python value:
                #    1. De-armor the value to get an encrypted bytestring.
                #    2. Decrypt the bytestring using the specified cipher.
                #    3. Unpad the bytestring using the cipher's block size.
                #    4. Decode the bytestring to a unicode string using the specified charset.
                return unpad(self.get_cipher().decrypt(dearmor(value, verify=self.check_armor)), self.cipher_class.block_size).decode(self.charset)
            return value or ''

        def get_db_prep_save(self, value, connection):
            if value and not self.is_encrypted(value):
                # If we have a value and it's not encrypted, do the following before storing in the database:
                #    1. Convert it to a unicode string (by calling unicode).
                #    2. Encode the unicode string according to the specified charset.
                #    3. Pad the bytestring for encryption, using the cipher's block size.
                #    4. Encrypt the padded bytestring using the specified cipher.
                #    5. Armor the encrypted bytestring for storage in the text field.
                return armor(self.get_cipher().encrypt(pad(unicode(value).encode(self.charset), self.cipher_class.block_size)))
            return value or ''

    class EncryptedTextField (BaseEncryptedField):
        __metaclass__ = models.SubfieldBase

        def formfield(self, **kwargs):
            defaults = {'widget': forms.Textarea}
            defaults.update(kwargs)
            return super(EncryptedTextField, self).formfield(**defaults)

    class EncryptedCharField (BaseEncryptedField):
        __metaclass__ = models.SubfieldBase
        description = _('String (up to %(max_length)s)')

        def __init__(self, **kwargs):
            # We don't want to restrict the max_length of an EncryptedCharField
            # because of the extra characters from encryption, but we'd like
            # to use the same interface as CharField
            kwargs.pop('max_length', None)
            super(EncryptedCharField, self).__init__(**kwargs)

        def formfield(self, **kwargs):
            defaults = {'widget': forms.TextInput}
            defaults.update(kwargs)
            return super(EncryptedCharField, self).formfield(**defaults)

    class EncryptedDecimalField (BaseEncryptedField):
        __metaclass__ = models.SubfieldBase
        description = _('Decimal number')

        def formfield(self, **kwargs):
            defaults = {'form_class': forms.DecimalField}
            defaults.update(kwargs)
            return super(EncryptedDecimalField, self).formfield(**defaults)

        def to_python(self, value):
            if value:
                return decimal.Decimal(super(EncryptedDecimalField, self).to_python(value))
            return value


    class EncryptedDateField (BaseEncryptedField):
        __metaclass__ = models.SubfieldBase
        description = _('Date (without time)')

        def __init__(self, auto_now=False, auto_now_add=False, **kwargs):
            self.auto_now, self.auto_now_add = auto_now, auto_now_add
            if auto_now or auto_now_add:
                kwargs['editable'] = False
                kwargs['blank'] = True
            super(EncryptedDateField, self).__init__(**kwargs)

        def formfield(self, **kwargs):
            defaults = {'widget': forms.DateInput}
            defaults.update(kwargs)
            return super(EncryptedDateField, self).formfield(**defaults)

        def to_python(self, value):
            if value in self.empty_values:
                return None
            unecrypted_value = super(EncryptedDateField, self).to_python(value)
            return self._parse_value(unecrypted_value)

        def value_to_string(self, obj):
            val = self._get_val_from_obj(obj)
            return '' if val is None else val.isoformat()

        def pre_save(self, model_instance, add):
            if self.auto_now or (self.auto_now_add and add):
                value = self._get_auto_now_value()
                setattr(model_instance, self.attname, value)
                return value
            else:
                return super(EncryptedDateField, self).pre_save(model_instance, add)

        def _parse_value(self, value):
            return models.DateField().to_python(value)

        def _get_auto_now_value(self):
            return datetime.date.today()

    class EncryptedDateTimeField (EncryptedDateField):
        __metaclass__ = models.SubfieldBase
        description = _('Date (with time)')

        def formfield(self, **kwargs):
            defaults = {'widget': forms.DateTimeInput}
            defaults.update(kwargs)
            return super(EncryptedDateTimeField, self).formfield(**defaults)

        def _parse_value(self, value):
            return models.DateTimeField().to_python(value)

        def _get_auto_now_value(self):
            return timezone.now()

    class EncryptedEmailField (BaseEncryptedField):
        __metaclass__ = models.SubfieldBase
        default_validators = [validators.validate_email]
        description = _('Email address')

        def formfield(self, **kwargs):
            defaults = {'form_class': forms.EmailField}
            defaults.update(kwargs)
            return super(EncryptedCharField, self).formfield(**defaults)

    # Django 1.7 custom lookups
    
    if django.VERSION >= (1, 7):
        
        from django.db.models.lookups import Lookup
    
        class EncryptedLookup (Lookup):
            cast = ''
            operator = '='
        
            def as_postgresql(self, qn, connection):
                lhs, lhs_params = self.process_lhs(qn, connection)
                rhs, rhs_params = self.process_rhs(qn, connection)
                params = lhs_params + [self.lhs.source.cipher_key] + rhs_params
                return "convert_from(decrypt(dearmor(%s), %%s, 'aes'), 'utf-8')%s %s %s" % (lhs, self.cast, self.operator, rhs), params

        class EncryptedExact (EncryptedLookup):
            lookup_name = 'exact'

        class EncryptedDecimalExact (EncryptedLookup):
            lookup_name = 'exact'
            cast = '::numeric'

        class EncryptedDecimalGreaterThan (EncryptedLookup):
            lookup_name = 'gt'
            cast = '::numeric'
            operator = '>'

        class EncryptedDecimalGreaterThanEqual (EncryptedLookup):
            lookup_name = 'gte'
            cast = '::numeric'
            operator = '>='

        class EncryptedDecimalLessThan (EncryptedLookup):
            lookup_name = 'lt'
            cast = '::numeric'
            operator = '<'

        class EncryptedDecimalLessThanEqual (EncryptedLookup):
            lookup_name = 'lte'
            cast = '::numeric'
            operator = '<='

        BaseEncryptedField.register_lookup(EncryptedExact)
    
        EncryptedDecimalField.register_lookup(EncryptedDecimalExact)
        EncryptedDecimalField.register_lookup(EncryptedDecimalGreaterThan)
        EncryptedDecimalField.register_lookup(EncryptedDecimalGreaterThanEqual)
        EncryptedDecimalField.register_lookup(EncryptedDecimalLessThan)
        EncryptedDecimalField.register_lookup(EncryptedDecimalLessThanEqual)
