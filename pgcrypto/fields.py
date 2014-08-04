import django
from django import forms
from django.conf import settings
from django.core import validators
from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from .base import armor, dearmor, pad, unpad, aes_pad_key
import datetime
import decimal


class BaseEncryptedField (models.Field):
    field_cast = ''

    def __init__(self, *args, **kwargs):
        # Just in case pgcrypto and/or pycrypto support more than AES/Blowfish.
        valid_ciphers = getattr(settings, 'PGCRYPTO_VALID_CIPHERS', ('AES', 'Blowfish'))
        self.cipher_name = kwargs.pop('cipher', getattr(settings, 'PGCRYPTO_DEFAULT_CIPHER', 'AES'))
        assert self.cipher_name in valid_ciphers
        self.cipher_key = kwargs.pop('key', getattr(settings, 'PGCRYPTO_DEFAULT_KEY', ''))
        self.charset = 'utf-8'
        if self.cipher_name == 'AES':
            self.cipher_key = aes_pad_key(self.cipher_key)
        mod = __import__('Crypto.Cipher', globals(), locals(), [self.cipher_name], -1)
        self.cipher_class = getattr(mod, self.cipher_name)
        self.check_armor = kwargs.pop('check_armor', True)
        super(BaseEncryptedField, self).__init__(*args, **kwargs)

    def get_internal_type(self):
        return 'TextField'

    def south_field_triple(self):
        """
        Describe the field to south for use in migrations.
        """
        from south.modelsinspector import introspector
        args, kwargs = introspector(self)
        return ("django.db.models.fields.TextField", args, kwargs)

    def deconstruct(self):
        """
        Deconstruct the field for Django 1.7+ migrations.
        """
        name, path, args, kwargs = super(BaseEncryptedField, self).deconstruct()
        kwargs.update({
            'cipher': self.cipher_name,
            'key': self.cipher_key,
            'check_armor': self.check_armor,
        })
        return name, path, args, kwargs

    def get_cipher(self):
        """
        Return a new Cipher object for each time we want to encrypt/decrypt. This is because
        pgcrypto expects a zeroed block for IV (initial value), but the IV on the cipher
        object is cumulatively updated each time encrypt/decrypt is called.
        """
        return self.cipher_class.new(self.cipher_key, self.cipher_class.MODE_CBC, b'\0' * self.cipher_class.block_size)

    def is_encrypted(self, value):
        """
        Returns whether the given value is encrypted (and armored) or not.
        """
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
    description = _('Text')

    def formfield(self, **kwargs):
        defaults = {'widget': forms.Textarea}
        defaults.update(kwargs)
        return super(EncryptedTextField, self).formfield(**defaults)


class EncryptedCharField (BaseEncryptedField):
    __metaclass__ = models.SubfieldBase
    description = _('String')

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


class EncryptedIntegerField (BaseEncryptedField):
    __metaclass__ = models.SubfieldBase
    description = _('Integer')
    field_cast = '::integer'

    def formfield(self, **kwargs):
        defaults = {'form_class': forms.IntegerField}
        defaults.update(kwargs)
        return super(EncryptedIntegerField, self).formfield(**defaults)

    def to_python(self, value):
        if value:
            return int(super(EncryptedIntegerField, self).to_python(value))
        return value


class EncryptedDecimalField (BaseEncryptedField):
    __metaclass__ = models.SubfieldBase
    description = _('Decimal number')
    field_cast = '::numeric'

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
    field_cast = '::date'

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
        unencrypted_value = super(EncryptedDateField, self).to_python(value)
        return self._parse_value(unencrypted_value)

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
    field_cast = 'timestamp with time zone'

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
        return super(EncryptedEmailField, self).formfield(**defaults)


if django.VERSION >= (1, 7):

    from django.db.models.lookups import Lookup

    class EncryptedLookup (Lookup):
        def as_postgresql(self, qn, connection):
            lhs, lhs_params = self.process_lhs(qn, connection)
            rhs, rhs_params = self.process_rhs(qn, connection)
            params = lhs_params + [self.lhs.source.cipher_key] + rhs_params
            rhs = connection.operators[self.lookup_name] % rhs
            cipher = {
                'AES': 'aes',
                'Blowfish': 'bf',
            }[self.lhs.source.cipher_name]
            return "convert_from(decrypt(dearmor(%s), %%s, '%s'), 'utf-8')%s %s" % (lhs, cipher, self.lhs.source.field_cast, rhs), params

    for lookup_name in ('exact', 'gt', 'gte', 'lt', 'lte'):
        class_name = 'EncryptedLookup_%s' % lookup_name
        lookup_class = type(class_name, (EncryptedLookup,), {'lookup_name': lookup_name})
        BaseEncryptedField.register_lookup(lookup_class)
