from django.db import models
import pgcrypto

class Employee (models.Model):
    name = models.CharField(max_length=200)
    ssn = pgcrypto.EncryptedCharField()
    salary = pgcrypto.EncryptedDecimalField()
    date_hired = pgcrypto.EncryptedDateField(cipher='Blowfish', key='datekey')

    def __unicode__(self):
        return self.name
