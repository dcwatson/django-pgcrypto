from django.db.models import Func


class Decrypt(Func):
    function = 'decrypt'
    template = "convert_from(%(function)s(dearmor(nullif(%(expressions)s, '')), %%s, %%s), %%s)"

    def as_sql(self, *args, **extra_context):
        sql, params = super().as_sql(*args, **extra_context)
        params.extend([self.field.cipher_key, self.field.cipher_name, self.field.charset])

        return sql, params
