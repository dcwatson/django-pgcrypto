from django.conf import settings
from django.db.models import Func

from .base import aes_pad_key


class Encrypt(Func):
    function = 'encrypt'
    template = "armor(%(function)s(convert_to(nullif(%(expressions)s, ''), %%s), %%s, %%s))"

    DEFAULT_CIPHER = getattr(settings, "PGCRYPTO_DEFAULT_CIPHER", "aes")
    DEFAULT_KEY = getattr(settings, "PGCRYPTO_DEFAULT_KEY", settings.SECRET_KEY)
    DEFAULT_CHARSET = "utf-8"

    def __init__(self, *args, **kwargs):
        self.cipher_name = kwargs.pop("cipher", self.DEFAULT_CIPHER).lower()
        self.cipher_key = kwargs.pop("key", self.DEFAULT_KEY)
        self.charset = kwargs.pop("charset", self.DEFAULT_CHARSET)

        if isinstance(self.cipher_key, str):
            self.cipher_key = self.cipher_key.encode(self.charset)
        if self.cipher_name == "aes":
            self.cipher_key = aes_pad_key(self.cipher_key)

        super().__init__(*args, **kwargs)

    def as_sql(self, *args, **extra_context):
        sql, params = super().as_sql(*args, **extra_context)

        charset = getattr(self.field, 'charset', self.charset)
        cipher_key = getattr(self.field, 'cipher_key', self.cipher_key)
        cipher_name = getattr(self.field, 'cipher_name', self.cipher_name)

        params.extend([charset, cipher_key, cipher_name])

        return sql, params


class Decrypt(Func):
    function = 'decrypt'
    template = "convert_from(%(function)s(dearmor(nullif(%(expressions)s, '')), %%s, %%s), %%s)"

    def as_sql(self, *args, **extra_context):
        sql, params = super().as_sql(*args, **extra_context)
        params.extend([self.field.cipher_key, self.field.cipher_name, self.field.charset])

        return sql, params
