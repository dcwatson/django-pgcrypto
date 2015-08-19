from django.db import models
from django.utils.encoding import python_2_unicode_compatible

import pgcrypto


@python_2_unicode_compatible
class Employee (models.Model):
    name = models.CharField(max_length=200)
    ssn = pgcrypto.EncryptedCharField('SSN')
    salary = pgcrypto.EncryptedDecimalField()
    date_hired = pgcrypto.EncryptedDateField(cipher='Blowfish', key='datekey')
    email = pgcrypto.EncryptedEmailField(unique=True, null=True)

    def __str__(self):
        return self.name
