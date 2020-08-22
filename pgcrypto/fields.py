import datetime
import decimal

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django import forms
from django.conf import settings
from django.core import validators
from django.db import models
from django.db.models.lookups import Lookup
from django.utils import timezone
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _

from .base import aes_pad_key, armor, dearmor, pad, unpad


class BaseEncryptedField(models.Field):
    field_cast = ""

    def __init__(self, *args, **kwargs):
        self.cipher_name = kwargs.pop("cipher", getattr(settings, "PGCRYPTO_DEFAULT_CIPHER", "aes")).lower()
        # Backwards-compatibility.
        if self.cipher_name == "blowfish":
            self.cipher_name = "bf"
        if self.cipher_name not in ("aes", "bf"):
            raise ValueError("Cipher must be 'aes' or 'bf'.")
        self.cipher_key = kwargs.pop("key", getattr(settings, "PGCRYPTO_DEFAULT_KEY", settings.SECRET_KEY))
        self.charset = kwargs.pop("charset", "utf-8")
        if isinstance(self.cipher_key, str):
            self.cipher_key = self.cipher_key.encode(self.charset)
        if self.cipher_name == "aes":
            self.cipher_key = aes_pad_key(self.cipher_key)
        self.check_armor = kwargs.pop("check_armor", True)
        self.versioned = kwargs.pop("versioned", False)
        super().__init__(*args, **kwargs)

    def get_internal_type(self):
        return "TextField"

    def deconstruct(self):
        """
        Deconstruct the field for Django 1.7+ migrations.
        """
        name, path, args, kwargs = super().deconstruct()
        kwargs.update(
            {
                "cipher": self.cipher_name,
                "charset": self.charset,
                "check_armor": self.check_armor,
                "versioned": self.versioned,
            }
        )
        return name, path, args, kwargs

    @property
    def algorithm(self):
        return {"aes": algorithms.AES, "bf": algorithms.Blowfish}[self.cipher_name]

    @property
    def block_size(self):
        return self.algorithm.block_size // 8

    def get_cipher(self):
        """
        Return a new Cipher object for each time we want to encrypt/decrypt. This is because
        pgcrypto expects a zeroed block for IV (initial value), but the IV on the cipher
        object is cumulatively updated each time encrypt/decrypt is called.
        """
        return Cipher(self.algorithm(self.cipher_key), modes.CBC(b"\0" * self.block_size), backend=default_backend())

    def encrypt(self, data):
        context = self.get_cipher().encryptor()
        return context.update(data) + context.finalize()

    def decrypt(self, data):
        context = self.get_cipher().decryptor()
        return context.update(data) + context.finalize()

    def is_encrypted(self, value):
        """
        Returns whether the given value is encrypted (and armored) or not.
        """
        return isinstance(value, str) and value.startswith("-----BEGIN")

    def to_python(self, value):
        if self.is_encrypted(value):
            # If we have an encrypted (armored, really) value, do the following when accessing it as a python value:
            #    1. De-armor the value to get an encrypted bytestring.
            #    2. Decrypt the bytestring using the specified cipher.
            #    3. Unpad the bytestring using the cipher's block size.
            #    4. Decode the bytestring to a unicode string using the specified charset.
            return unpad(self.decrypt(dearmor(value, verify=self.check_armor)), self.block_size).decode(self.charset)
        return value

    def from_db_value(self, value, expression, connection):
        return self.to_python(value)

    def get_db_prep_save(self, value, connection):
        if value and not self.is_encrypted(value):
            # If we have a value and it's not encrypted, do the following before storing in the database:
            #    1. Convert it to a unicode string (by calling unicode).
            #    2. Encode the unicode string according to the specified charset.
            #    3. Pad the bytestring for encryption, using the cipher's block size.
            #    4. Encrypt the padded bytestring using the specified cipher.
            #    5. Armor the encrypted bytestring for storage in the text field.
            return armor(
                self.encrypt(pad(force_str(value).encode(self.charset), self.block_size)), versioned=self.versioned,
            )
        return value


class EncryptedTextField(BaseEncryptedField):
    description = _("Text")

    def formfield(self, **kwargs):
        defaults = {"widget": forms.Textarea}
        defaults.update(kwargs)
        return super().formfield(**defaults)


class EncryptedCharField(BaseEncryptedField):
    description = _("String")

    def __init__(self, *args, **kwargs):
        # We don't want to restrict the max_length of an EncryptedCharField
        # because of the extra characters from encryption, but we'd like
        # to use the same interface as CharField
        kwargs.pop("max_length", None)
        super().__init__(*args, **kwargs)

    def formfield(self, **kwargs):
        defaults = {"widget": forms.TextInput}
        defaults.update(kwargs)
        return super().formfield(**defaults)


class EncryptedIntegerField(BaseEncryptedField):
    description = _("Integer")
    field_cast = "::integer"

    def formfield(self, **kwargs):
        defaults = {"form_class": forms.IntegerField}
        defaults.update(kwargs)
        return super().formfield(**defaults)

    def to_python(self, value):
        if value:
            return int(super().to_python(value))
        return value


class EncryptedDecimalField(BaseEncryptedField):
    description = _("Decimal number")
    field_cast = "::numeric"

    def formfield(self, **kwargs):
        defaults = {"form_class": forms.DecimalField}
        defaults.update(kwargs)
        return super().formfield(**defaults)

    def to_python(self, value):
        if value:
            return decimal.Decimal(super().to_python(value))
        return value


class EncryptedDateField(BaseEncryptedField):
    description = _("Date (without time)")
    field_cast = "::date"

    def __init__(self, verbose_name=None, name=None, auto_now=False, auto_now_add=False, **kwargs):
        self.auto_now, self.auto_now_add = auto_now, auto_now_add
        if auto_now or auto_now_add:
            kwargs["editable"] = False
            kwargs["blank"] = True
        super().__init__(verbose_name, name, **kwargs)

    def formfield(self, **kwargs):
        defaults = {"form_class": forms.DateField}
        defaults.update(kwargs)
        return super().formfield(**defaults)

    def to_python(self, value):
        if value in self.empty_values:
            return None
        unencrypted_value = super().to_python(value)
        return self._parse_value(unencrypted_value)

    def value_to_string(self, obj):
        val = self.value_from_object(obj)
        return "" if val is None else val.isoformat()

    def pre_save(self, model_instance, add):
        if self.auto_now or (self.auto_now_add and add):
            value = self._get_auto_now_value()
            setattr(model_instance, self.attname, value)
            return value
        else:
            return super().pre_save(model_instance, add)

    def _parse_value(self, value):
        return models.DateField().to_python(value)

    def _get_auto_now_value(self):
        return datetime.date.today()


class EncryptedDateTimeField(EncryptedDateField):
    description = _("Date (with time)")
    field_cast = "timestamp with time zone"

    def formfield(self, **kwargs):
        defaults = {"form_class": forms.DateTimeField}
        defaults.update(kwargs)
        return super().formfield(**defaults)

    def _parse_value(self, value):
        return models.DateTimeField().to_python(value)

    def _get_auto_now_value(self):
        return timezone.now()


class EncryptedEmailField(BaseEncryptedField):
    default_validators = [validators.validate_email]
    description = _("Email address")

    def formfield(self, **kwargs):
        defaults = {"form_class": forms.EmailField}
        defaults.update(kwargs)
        return super().formfield(**defaults)


class EncryptedLookup(Lookup):
    def as_postgresql(self, qn, connection):
        lhs, lhs_params = self.process_lhs(qn, connection)
        rhs, rhs_params = self.process_rhs(qn, connection)
        rhs = connection.operators[self.lookup_name] % rhs
        if self.lookup_name == "exact" and rhs_params == [""]:
            # Special case when looking for blank values, don't try to dearmor/decrypt (#23).
            return "%s %s" % (lhs, rhs), lhs_params + rhs_params
        params = lhs_params + [self.lhs.output_field.cipher_key] + rhs_params
        return (
            "convert_from(decrypt(dearmor(%s), %%s, '%s'), 'utf-8')%s %s"
            % (lhs, self.lhs.output_field.cipher_name, self.lhs.output_field.field_cast, rhs),
            params,
        )


for lookup_name in ("exact", "gt", "gte", "lt", "lte"):
    class_name = "EncryptedLookup_%s" % lookup_name
    lookup_class = type(class_name, (EncryptedLookup,), {"lookup_name": lookup_name})
    BaseEncryptedField.register_lookup(lookup_class)
