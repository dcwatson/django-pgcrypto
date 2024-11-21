from django.conf import settings
from django.db.models import Func

from .base import aes_pad_key


class CryptoFunc(Func):
    def __init__(self, *args, **kwargs):
        self.params = {
            "cipher_name": kwargs.pop("cipher", None),
            "cipher_key": kwargs.pop("key", None),
            "charset": kwargs.pop("charset", None),
        }

        super().__init__(*args, **kwargs)

    def get_params(self):
        cipher_name = self.params["cipher_name"] or getattr(
            self.field,
            "cipher_name",
            getattr(settings, "PGCRYPTO_DEFAULT_CIPHER", "aes"),
        )
        cipher_key = self.params["cipher_key"] or getattr(
            self.field,
            "cipher_key",
            getattr(settings, "PGCRYPTO_DEFAULT_KEY", settings.SECRET_KEY),
        )
        charset = self.params["charset"] or getattr(self.field, "charset", "utf-8")

        if cipher_name == "aes":
            # If this is from self.field, it's already padded, but this is still safe
            # to call again.
            cipher_key = aes_pad_key(cipher_key)

        return cipher_name, cipher_key, charset


class Encrypt(CryptoFunc):
    function = "encrypt"
    template = (
        "armor(%(function)s(convert_to(nullif(%(expressions)s, ''), %%s), %%s, %%s))"
    )

    def as_sql(self, *args, **extra_context):
        sql, params = super().as_sql(*args, **extra_context)
        cipher_name, cipher_key, charset = self.get_params()
        params.extend([charset, cipher_key, cipher_name])

        return sql, params


class Decrypt(CryptoFunc):
    function = "decrypt"
    template = "convert_from(%(function)s(dearmor(nullif(%(expressions)s, '')), %%s, %%s), %%s)"

    def as_sql(self, *args, **extra_context):
        sql, params = super().as_sql(*args, **extra_context)
        cipher_name, cipher_key, charset = self.get_params()
        params.extend([cipher_key, cipher_name, charset])

        return sql, params
